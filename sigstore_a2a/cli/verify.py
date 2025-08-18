from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ..verifier import AgentCardVerifier, IdentityConstraints

console = Console()


@click.command("verify")
@click.argument("signed_card", type=click.Path(exists=True, path_type=Path))
@click.option("--staging", is_flag=True, help="Use Sigstore staging environment")
@click.option("--trust_config", type=click.Path(path_type=Path), help="The client trust configuration to use")
@click.option("--repository", help="Required repository constraint (e.g., owner/repo)")
@click.option("--workflow", help="Required workflow name constraint")
@click.option("--actor", help="Required actor/user constraint")
@click.option("--issuer", help="Required OIDC issuer constraint")
@click.pass_context
def verify_cmd(
    ctx: click.Context,
    signed_card: Path,
    staging: bool,
    trust_config: Path | None,
    repository: str | None,
    workflow: str | None,
    actor: str | None,
    issuer: str | None,
) -> None:
    """Verify a signed A2A Agent Card.

    This command verifies the cryptographic signature and optionally checks
    identity constraints for a signed Agent Card.

    Examples:
        sigstore-a2a verify signed-card.json
        sigstore-a2a verify signed-card.json --repository owner/repo
        sigstore-a2a verify signed-card.json --workflow build-agent --actor user
    """
    verbose = ctx.obj.get("verbose", False)

    constraints = None
    if any([repository, workflow, actor, issuer]):
        constraints = IdentityConstraints(repository=repository, workflow=workflow, actor=actor, issuer=issuer)

        if verbose:
            console.print("[blue]Identity constraints:[/blue]")
            if repository:
                console.print(f"  Repository: {repository}")
            if workflow:
                console.print(f"  Workflow: {workflow}")
            if actor:
                console.print(f"  Actor: {actor}")
            if issuer:
                console.print(f"  Issuer: {issuer}")

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
