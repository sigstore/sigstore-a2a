# Copyright 2025 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..provenance import ProvenanceBuilder
from ..signer import AgentCardSigner
from ..utils.ci import detect_ci_environment

console = Console()


@click.command("sign")
@click.argument(
    "agent_card",
    type=click.Path(exists=True, path_type=Path),
    metavar="AGENT_CARD_JSON",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    metavar="OUTPUT_PATH",
    help="Path to write the signed Agent Card JSON.",
)
@click.option(
    "--use_ambient_credentials",
    is_flag=True,
    help="Use ambient CI/OIDC credentials if available.",
)
@click.option(
    "--staging",
    is_flag=True,
    help="Use Sigstore staging trust roots.",
)
@click.option(
    "--trust_config",
    type=click.Path(path_type=Path),
    metavar="CLIENT_TRUST_JSON",
    help="Path to Sigstore ClientTrustConfig JSON.",
)
@click.option(
    "--provenance",
    is_flag=True,
    help="Generate and embed SLSA provenance.",
)
@click.option(
    "--identity_token",
    type=str,
    metavar="TOKEN",
    help="Fixed OIDC identity token to use.",
)
@click.option(
    "--client_id",
    type=str,
    metavar="CLIENT_ID",
    help="OpenID Connect client ID for OAuth2.",
)
@click.option(
    "--client_secret",
    type=str,
    metavar="CLIENT_SECRET",
    help="OpenID Connect client secret for OAuth2.",
)
@click.option(
    "--repository",
    type=str,
    metavar="OWNER/REPO",
    help="Repository for provenance metadata.",
)
@click.option(
    "--commit_sha",
    type=str,
    metavar="COMMIT_SHA",
    help="Commit SHA for provenance metadata.",
)
@click.option(
    "--workflow_ref",
    type=str,
    metavar="WORKFLOW_REF",
    help="Workflow ref for provenance (e.g., .github/workflows/ci.yml@refs/heads/main).",
)
@click.pass_context
def sign_cmd(
    ctx: click.Context,
    agent_card: Path,
    output: Path | None,
    use_ambient_credentials: bool,
    staging: bool,
    trust_config: Path | None = None,
    provenance: bool = False,
    identity_token: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    repository: str | None = None,
    commit_sha: str | None = None,
    workflow_ref: str | None = None,
) -> None:
    """
    Sign an A2A Agent Card using Sigstore keyless signing and (optionally) attach SLSA provenance.

    This command:
      • Loads an Agent Card JSON file.
      • Signs the card using Sigstore’s keyless flow, producing a Sigstore Bundle that is embedded into the output.
      • (Optionally) generates and embeds an SLSA provenance attestation if --provenance is specified.
      • Writes a *.signed.json artifact (or the path given via --output).

    Credential resolution order:
      1) --identity_token TOKEN (if provided)
      2) --use_ambient_credentials (e.g., GitHub/GitLab OIDC in CI) if set
      3) Interactive OAuth/device flow (local development fallback)

    Trust roots:
      • --staging uses Sigstore’s staging Fulcio/Rekor.
      • --trust_config points to a Sigstore Client Trust Configuration JSON (e.g., your private Sigstore instance).
      • If neither is supplied, the production trust root is used.

    Provenance (opt-in via --provenance):
      • When enabled, attempts to build a SLSA provenance attestation.
      • You can override or supply build metadata with --repository, --commit_sha, --workflow_ref.

    Output:
      • Defaults to <agent_card_basename>.signed.json in the same directory.
      • Use --output to pick a custom path.

    Examples:
      # Minimal: sign with production trust and interactive auth (local dev)
      sigstore-a2a sign agent-card.json

      # Write to a specific path
      sigstore-a2a sign agent-card.json --output signed-card.json

      # Use Sigstore staging (good for sandbox testing)
      sigstore-a2a sign agent-card.json --staging

      # Use a private trust root (RHTAS); trust_config is your client trust JSON
      sigstore-a2a sign agent-card.json --trust_config ./signing_config.json

      # Use a pre-fetched OIDC token (e.g., exported to $IDENTITY_TOKEN)
      sigstore-a2a sign agent-card.json --identity_token "$IDENTITY_TOKEN"

      # Prefer ambient CI credentials (GitHub Actions, etc.)
      sigstore-a2a sign agent-card.json --use_ambient_credentials

      # Attach SLSA provenance with repo/commit/workflow metadata
      sigstore-a2a sign agent-card.json --provenance \
        --repository myorg/myrepo \
        --commit_sha $GITHUB_SHA \
        --workflow_ref ".github/workflows/ci.yml@refs/heads/main"

      # Combine: private trust root + provenance + ambient CI credentials
      sigstore-a2a sign agent-card.json \
        --trust_config ./signing_config.json \
        --provenance \
        --use_ambient_credentials
    """
    verbose = bool(ctx.obj.get("verbose")) if isinstance(ctx.obj, dict) else False

    if use_ambient_credentials and verbose:
        ci_env = detect_ci_environment()
        console.print(
            f"[blue]Detected CI environment: {ci_env}[/blue]"
            if ci_env
            else "[yellow]No CI environment detected; attempting ambient credentials anyway[/yellow]"
        )

    if trust_config is not None and not trust_config.exists():
        raise click.ClickException(f"Trust config not found: {trust_config}")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Initializing signer...", total=None)
            signer = AgentCardSigner(
                staging=staging,
                trust_config=trust_config,
                identity_token=identity_token,
                client_id=client_id,
                client_secret=client_secret,
                use_ambient_credentials=use_ambient_credentials,
                verbose=verbose,
            )

            # Optionally generate provenance
            provenance_bundle = None
            if provenance:
                progress.add_task("Generating SLSA provenance...", total=None)
                try:
                    provenance_builder = ProvenanceBuilder()
                    provenance_bundle = provenance_builder.build_provenance(
                        agent_card=agent_card,
                        source_repo=repository,
                        commit_sha=commit_sha,
                        workflow_ref=workflow_ref,
                    )
                    if verbose:
                        console.print("[green]SLSA provenance generated successfully[/green]")
                except Exception as e:
                    msg = f"Failed to generate provenance: {e}"
                    console.print(f"[yellow]{msg}[/yellow]" if not verbose else f"[yellow]{msg}[/yellow]")

            progress.add_task("Signing Agent Card...", total=None)
            signed_card = signer.sign_agent_card(agent_card=agent_card, provenance_bundle=provenance_bundle)

            out_path = output or agent_card.with_suffix(".signed.json")

            progress.add_task("Writing signed Agent Card...", total=None)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(
                    signed_card.to_dict(),
                    f,
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )

        console.print("[green]✓[/green] Agent Card signed successfully")
        console.print(f"[blue]Signed card written to: {out_path}[/blue]")

        if verbose:
            sig_bundle = None
            sig_bundle = getattr(getattr(signed_card, "attestations", None), "signature_bundle", None) or sig_bundle

            if sig_bundle is not None:
                ts = getattr(sig_bundle, "timestamp", None)
                if ts:
                    console.print(f"[dim]Signature timestamp: {ts}[/dim]")

                tlog = getattr(sig_bundle, "transparency_log_entry", None)
                if tlog:
                    console.print("[dim]Transparency log entry created[/dim]")

            prov = None
            prov = getattr(getattr(signed_card, "attestations", None), "provenance_bundle", None) or prov
            if prov:
                console.print("[dim]SLSA provenance included[/dim]")

    except click.ClickException:
        raise
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to sign Agent Card: {e}")
        if verbose:
            console.print_exception()
        raise click.ClickException(str(e)) from e
