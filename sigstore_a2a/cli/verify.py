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

from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ..verifier import AgentCardVerifier, IdentityConstraints

console = Console()


@click.command("verify")
@click.argument(
    "signed_card",
    type=click.Path(exists=True, path_type=Path),
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
    "--repository",
    metavar="OWNER/REPO",
    help="Required repository constraint.",
)
@click.option(
    "--workflow",
    metavar="WORKFLOW_NAME",
    help="Required workflow name constraint.",
)
@click.option(
    "--identity",
    type=str,
    metavar="SUBJECT",
    required=True,
    help="Expected subject (email or URI) bound in the signing certificate.",
)
@click.option(
    "--identity_provider",
    type=str,
    metavar="PROVIDER_URL",
    required=True,
    help="Expected identity provider/issuer (e.g., https://accounts.google.com).",
)
@click.pass_context
def verify_cmd(
    ctx: click.Context,
    signed_card: Path,
    staging: bool,
    identity_provider: str,
    identity: str | None = None,
    trust_config: Path | None = None,
    repository: str | None = None,
    workflow: str | None = None,
) -> None:
    """
    Verify a signed A2A Agent Card using a Sigstore Bundle and identity constraints.

    This command:
      • Loads a signed Agent Card JSON file.
      • Extracts the embedded Sigstore bundle and verifies the DSSE signature,
        certificate chain, and Rekor transparency log inclusion (per trust root).
      • Enforces signer identity checks via:
          – --identity_provider (required): expected OIDC issuer URL.
      • (Optionally) enforces additional constraints such as repository, workflow,
        or identity when the corresponding flags are provided.

    Trust roots:
      • --staging uses Sigstore’s staging Fulcio/Rekor.
      • --trust_config points to a Sigstore Client Trust Configuration JSON
        (e.g., a private Sigstore instance).
      • If neither is supplied, the production trust root is used.
      • Do not combine --staging and --trust_config.

    Output/behavior:
      • Exits non-zero on any verification or constraint failure.
      • With --verbose, prints certificate/identity details for diagnostics.

    Examples:
      # Minimal verification with required identity + IdP
      sigstore-a2a verify \
        --identity dev@example.com \
        --identity_provider https://accounts.google.com \
        signed-card.json

      # Enforce GitHub repository + workflow constraints
      sigstore-a2a verify \
        --identity "https://github.com/owner/repo/.github/workflows/ci.yml@refs/heads/main" \
        --identity_provider https://token.actions.githubusercontent.com \
        --repository owner/repo \
        --workflow ci \
        signed-card.json

      # Use a private trust configuration
      sigstore-a2a verify \
        --identity dev@example.com \
        --identity_provider https://accounts.google.com \
        --trust_config ./client-trust-config.json \
        signed-card.json

      # Use Sigstore staging for sandbox testing
      sigstore-a2a verify \
        --identity dev@example.com \
        --identity_provider https://accounts.google.com \
        --staging \
        signed-card.json
    """
    verbose = ctx.obj.get("verbose", False)

    constraints = None
    if any([repository, workflow, identity, identity_provider]):
        constraints = IdentityConstraints(
            repository=repository, workflow=workflow, identity=identity, identity_provider=identity_provider
        )

        if verbose:
            console.print("[blue]Identity constraints:[/blue]")
            if repository:
                console.print(f"  Repository: {repository}")
            if workflow:
                console.print(f"  Workflow: {workflow}")
            if identity:
                console.print(f"  Identity: {identity}")
            if identity_provider:
                console.print(f"  Issuer: {identity_provider}")

    try:
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True
        ) as progress:
            progress.add_task("Initializing verifier...", total=None)
            verifier = AgentCardVerifier(staging=staging, trust_config=trust_config)

            progress.add_task("Verifying signature...", total=None)
            result = verifier.verify_signed_card(signed_card, constraints)

        if result.valid:
            console.print("[green]✓[/green] Agent Card signature is valid")

            if result.agent_card:
                table = Table(title="Agent Card Details")
                table.add_column("Field", style="cyan")
                table.add_column("Value", style="white")

                table.add_row("Name", result.agent_card.name)
                table.add_row("Version", result.agent_card.version)
                table.add_row("URL", str(result.agent_card.url))
                table.add_row("Protocol Version", result.agent_card.protocol_version)

                if result.agent_card.provider:
                    table.add_row("Provider", result.agent_card.provider.organization)

                console.print(table)

            if verbose and result.identity:
                identity_table = Table(title="Signing Identity", width=120)
                identity_table.add_column("Claim", style="cyan", width=30, no_wrap=False)
                identity_table.add_column("Value", style="white", width=90, no_wrap=False)

                for key, value in result.identity.items():
                    identity_table.add_row(key.replace("_", " ").title(), str(value))

                console.print(identity_table)

            if verbose and result.certificate:
                console.print(f"[dim]Certificate subject: {result.certificate.subject.rfc4514_string()}[/dim]")
                console.print(f"[dim]Certificate not valid before: {result.certificate.not_valid_before_utc}[/dim]")
                console.print(f"[dim]Certificate not valid after: {result.certificate.not_valid_after_utc}[/dim]")

        else:
            console.print("[red]✗[/red] Agent Card signature verification failed")

            for error in result.errors:
                console.print(f"[red]Error:[/red] {error}")

            raise click.ClickException("Signature verification failed")

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to verify Agent Card: {e}")
        if verbose:
            console.print_exception()
        raise click.ClickException(str(e)) from e
