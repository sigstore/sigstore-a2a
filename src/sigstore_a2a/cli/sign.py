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
@click.argument("agent_card", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output path for signed Agent Card (default: <input>.signed.json)",
)
@click.option("--staging", is_flag=True, help="Use Sigstore staging environment")
@click.option("--trust_config", type=click.Path(path_type=Path), help="The client trust configuration to use")
@click.option("--no-provenance", is_flag=True, help="Skip SLSA provenance generation")
@click.option("--repository", help="Override repository for provenance (e.g., owner/repo)")
@click.option("--commit-sha", help="Override commit SHA for provenance")
@click.option("--workflow-ref", help="Override workflow reference for provenance")
@click.pass_context
def sign_cmd(
    ctx: click.Context,
    agent_card: Path,
    output: Path | None,
    staging: bool,
    trust_config: Path | None,
    no_provenance: bool,
    repository: str | None,
    commit_sha: str | None,
    workflow_ref: str | None,
) -> None:
    """Sign an A2A Agent Card using Sigstore keyless signing.

    This command signs an Agent Card JSON file using Sigstore's keyless
    signing infrastructure. It automatically detects CI/CD environment
    credentials and optionally generates SLSA provenance attestations.

    Examples:
        sigstore-a2a sign agent-card.json
        sigstore-a2a sign agent-card.json --output signed-card.json
        sigstore-a2a sign agent-card.json --no-provenance
    """
    verbose = ctx.obj.get("verbose", False)

    # Check for CI environment
    ci_env = detect_ci_environment()
    if verbose:
        if ci_env:
            console.print(f"[blue]Detected CI environment: {ci_env}[/blue]")
        else:
            console.print("[yellow]No CI environment detected, using ambient credentials[/yellow]")

    try:
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True
        ) as progress:
            # Initialize signer
            progress.add_task("Initializing signer...", total=None)
            signer = AgentCardSigner(staging=staging, trust_config=trust_config)

            # Generate provenance if requested
            provenance_bundle = None
            if not no_provenance:
                progress.add_task("Generating SLSA provenance...", total=None)
                try:
                    provenance_builder = ProvenanceBuilder()
                    provenance_bundle = provenance_builder.build_provenance(
                        agent_card=agent_card, source_repo=repository, commit_sha=commit_sha, workflow_ref=workflow_ref
                    )
                    if verbose:
                        console.print("[green]SLSA provenance generated successfully[/green]")
                except Exception as e:
                    if verbose:
                        console.print(f"[yellow]Failed to generate provenance: {e}[/yellow]")
                    else:
                        console.print("[yellow]Warning: Failed to generate provenance[/yellow]")

            # Sign the agent card
            progress.add_task("Signing Agent Card...", total=None)
            signed_card = signer.sign_agent_card(agent_card=agent_card, provenance_bundle=provenance_bundle)

            # Determine output path
            if output is None:
                output = agent_card.with_suffix(".signed.json")

            # Write signed card
            progress.add_task("Writing signed Agent Card...", total=None)
            with open(output, "w") as f:
                json.dump(signed_card.model_dump(by_alias=True), f, indent=2, default=str)

        console.print("[green]✓[/green] Agent Card signed successfully")
        console.print(f"[blue]Signed card written to: {output}[/blue]")

        if verbose:
            # Show signing details
            sig_bundle = signed_card.verification_material.signature_bundle
            console.print(f"[dim]Signature timestamp: {sig_bundle.timestamp}[/dim]")
            if sig_bundle.transparency_log_entry:
                console.print("[dim]Transparency log entry created[/dim]")
            if signed_card.verification_material.provenance_bundle:
                console.print("[dim]SLSA provenance included[/dim]")

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to sign Agent Card: {e}")
        if verbose:
            console.print_exception()
        raise click.ClickException(str(e)) from e
