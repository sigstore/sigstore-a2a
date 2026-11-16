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

from .._signing.verify_ec_key import ECKeyAgentCardVerifier

console = Console()


@click.command("pki-verify")
@click.argument("signed_card", type=click.Path(exists=True, path_type=Path))
@click.option("--public-key", required=True, type=click.Path(exists=True, path_type=Path), help="PEM EC public key.")
@click.pass_context
def pki_verify_cmd(ctx: click.Context, signed_card: Path, public_key: Path) -> None:
    """Verify a signed A2A Agent Card using an EC public key."""
    verbose = ctx.obj.get("verbose", False)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Initializing EC key verifier...", total=None)
            verifier = ECKeyAgentCardVerifier(public_key_path=public_key)

            progress.add_task("Verifying signature...", total=None)
            result = verifier.verify_signed_card(signed_card)

        if result.valid:
            console.print("[green]✓[/green] Agent Card signature is valid (EC key)")

            if result.agent_card:
                table = Table(title="Agent Card Details")
                table.add_column("Field", style="cyan")
                table.add_column("Value", style="white")
                table.add_row("Name", result.agent_card.name)
                table.add_row("Version", result.agent_card.version)

                url = ""
                if result.agent_card.supported_interfaces:
                    url = str(result.agent_card.supported_interfaces[0].url)
                elif result.raw_card_data.get("url"):
                    url = str(result.raw_card_data["url"])
                if url:
                    table.add_row("URL", url)
                console.print(table)
        else:
            console.print("[red]✗[/red] Agent Card signature verification failed")
            for error in result.errors:
                console.print(f"[red]Error:[/red] {error}")
            raise click.ClickException("Signature verification failed")

    except click.ClickException:
        raise
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to verify Agent Card: {e}")
        if verbose:
            console.print_exception()
        raise click.ClickException(str(e)) from e
