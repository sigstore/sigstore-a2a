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

from .._signing.sign_ec_key import ECKeyAgentCardSigner

console = Console()


@click.command("pki-sign")
@click.argument("agent_card", type=click.Path(exists=True, path_type=Path))
@click.option("--private-key", required=True, type=click.Path(exists=True, path_type=Path), help="PEM EC private key.")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output path for the signed Agent Card.")
@click.option("--provenance", is_flag=True, default=False, help="Generate and embed SLSA provenance.")
@click.option("--repository", type=str, help="Repository for provenance metadata.")
@click.option("--commit_sha", type=str, help="Commit SHA for provenance metadata.")
@click.option("--workflow_ref", type=str, help="Workflow ref for provenance metadata.")
@click.pass_context
def pki_sign_cmd(
    ctx: click.Context,
    agent_card: Path,
    private_key: Path,
    output: Path | None,
    provenance: bool,
    repository: str | None,
    commit_sha: str | None,
    workflow_ref: str | None,
) -> None:
    """Sign an A2A Agent Card using an EC private key."""
    verbose = ctx.obj.get("verbose", False)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Initializing EC key signer...", total=None)
            signer = ECKeyAgentCardSigner(private_key_path=private_key)

            provenance_bundle = None
            if provenance:
                progress.add_task("Generating SLSA provenance...", total=None)
                from ..provenance import ProvenanceBuilder

                provenance_bundle = ProvenanceBuilder().build_provenance(
                    agent_card=agent_card,
                    source_repo=repository,
                    commit_sha=commit_sha,
                    workflow_ref=workflow_ref,
                )
                if verbose:
                    console.print("[green]SLSA provenance generated[/green]")

            progress.add_task("Signing Agent Card...", total=None)
            signed_card = signer.sign_agent_card(agent_card, provenance_bundle=provenance_bundle)

            out_path = output or agent_card.with_suffix(".signed.json")
            progress.add_task("Writing signed Agent Card...", total=None)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(signed_card.to_dict(), f, indent=2, ensure_ascii=False, default=str)

        console.print("[green]✓[/green] Agent Card signed successfully (EC key)")
        console.print(f"[blue]Signed card written to: {out_path}[/blue]")
        if provenance_bundle and verbose:
            console.print("[dim]SLSA provenance included[/dim]")

    except click.ClickException:
        raise
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to sign Agent Card: {e}")
        if verbose:
            console.print_exception()
        raise click.ClickException(str(e)) from e
