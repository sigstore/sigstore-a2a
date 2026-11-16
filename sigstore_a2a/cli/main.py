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

from collections.abc import Iterable
from pathlib import Path

import click
from rich.console import Console

import sigstore_a2a

console = Console()


# ---------------------------------------------------------------------------
# PKI method group: defaults to "sigstore" when no subcommand is given
# ---------------------------------------------------------------------------
class _PKICmdGroup(click.Group):
    """Custom group that defaults to the ``sigstore`` subcommand."""

    _supported_modes = ["sigstore", "key"]

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        if cmd_name in self._supported_modes:
            return super().get_command(ctx, cmd_name)
        return super().get_command(ctx, "sigstore")

    def resolve_command(
        self, ctx: click.Context, args: list[str] | Iterable[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        args = list(args)
        if args and args[0] in self._supported_modes:
            return super().resolve_command(ctx, args)
        cmd = super().get_command(ctx, "sigstore")
        return cmd.name, cmd, args


# ---------------------------------------------------------------------------
# Reusable option decorators
# ---------------------------------------------------------------------------

# Trust / instance toggles (mutually exclusive)
_sigstore_staging = click.option(
    "--staging",
    type=bool,
    is_flag=True,
    help="Use Sigstore staging environment. Mutually exclusive with --instance and --trust_config.",
)
_instance = click.option(
    "--instance",
    type=str,
    metavar="URL",
    help="Sigstore instance URL (TUF-bootstrapped). Mutually exclusive with --staging and --trust_config.",
)
_trust_config = click.option(
    "--trust_config",
    type=click.Path(path_type=Path),
    help="Path to ClientTrustConfig JSON. Mutually exclusive with --staging and --instance.",
)


def _validate_trust_options(staging: bool, instance: str | None, trust_config: Path | None) -> None:
    opts = sum(bool(x) for x in [staging, instance, trust_config])
    if opts > 1:
        raise click.ClickException("Options --staging, --instance, and --trust_config are mutually exclusive")


# Signing inputs / outputs
_agent_card_arg = click.argument("agent_card", type=click.Path(exists=True, path_type=Path))
_signed_card_arg = click.argument("signed_card", type=click.Path(exists=True, path_type=Path))
_output = click.option("-o", "--output", type=click.Path(path_type=Path), help="Output path for the signed Agent Card.")
_provenance = click.option("--provenance", is_flag=True, default=False, type=bool, help="Include SLSA provenance.")

# OIDC / OAuth
_identity_token = click.option("--identity_token", type=str, metavar="TOKEN", help="Fixed OIDC identity token.")
_client_id = click.option("--client_id", type=str, metavar="ID", help="Custom OIDC client ID.")
_client_secret = click.option("--client_secret", type=str, metavar="SECRET", help="Custom OIDC client secret.")
_use_ambient_credentials = click.option(
    "--use_ambient_credentials", type=bool, is_flag=True, help="Use ambient CI/OIDC credentials."
)

# Provenance overrides
_repository = click.option("--repository", help="Override/require repository.")
_commit_sha = click.option("--commit_sha", help="Override commit SHA.")
_workflow_ref = click.option("--workflow_ref", help="Override workflow reference.")

# Verification constraints
_identity = click.option("--identity", type=str, metavar="IDENTITY", help="Expected signer identity.")
_identity_provider = click.option(
    "--identity_provider", type=str, metavar="IDENTITY_PROVIDER", required=True, help="Expected identity provider."
)
_workflow = click.option("--workflow", help="Required workflow name constraint.")

# Serve options
_host = click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind to.")
_port = click.option("--port", default=8080, type=int, show_default=True, help="Port to bind to.")
_no_verify = click.option("--no-verify", is_flag=True, help="Skip signature verification on startup.")
_reload = click.option("--reload", is_flag=True, help="Enable auto-reload for development.")


# ===================================================================
# CLI root
# ===================================================================
@click.group(
    context_settings=dict(help_option_names=["-h", "--help"]),
    epilog="Check https://sigstore.github.io/sigstore-a2a for documentation and more details.",
)
@click.version_option(sigstore_a2a.__version__, "--version")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """sigstore-a2a command line."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


# ===================================================================
# sign  (group — subcommands: sigstore | key)
# ===================================================================
@cli.group(name="sign", subcommand_metavar="PKI_METHOD", cls=_PKICmdGroup)
@click.pass_context
def _sign(ctx: click.Context) -> None:
    """Sign an A2A Agent Card.

    Supported PKI methods (subcommands): sigstore (default), key.
    If no method is given, sigstore keyless signing is used.
    """


@_sign.command(name="sigstore")
@_use_ambient_credentials
@_agent_card_arg
@_output
@_sigstore_staging
@_instance
@_trust_config
@_provenance
@_identity_token
@_client_id
@_client_secret
@_repository
@_commit_sha
@_workflow_ref
@click.pass_context
def _sign_sigstore(ctx: click.Context, **kwargs):
    """Sign using Sigstore keyless signing (DEFAULT).

    Examples:

      sigstore-a2a sign agent-card.json
      sigstore-a2a sign sigstore agent-card.json --staging
    """
    try:
        from .sign import sign_cmd

        return ctx.invoke(sign_cmd, **kwargs)
    except ImportError as e:
        console.print(f"[red]Error:[/red] Failed to import signing dependencies: {e}")


@_sign.command(name="key")
@_agent_card_arg
@click.option("--private-key", required=True, type=click.Path(exists=True, path_type=Path), help="PEM EC private key.")
@_output
@_provenance
@_repository
@_commit_sha
@_workflow_ref
@click.pass_context
def _sign_key(
    ctx: click.Context,
    agent_card: Path,
    private_key: Path,
    output: Path | None,
    provenance: bool,
    repository: str | None,
    commit_sha: str | None,
    workflow_ref: str | None,
):
    """Sign using an EC private key.

    Examples:

      sigstore-a2a sign key agent-card.json --private-key key.pem
      sigstore-a2a sign key agent-card.json --private-key key.pem --provenance
    """
    try:
        from .pki_sign import pki_sign_cmd

        return ctx.invoke(
            pki_sign_cmd,
            agent_card=agent_card,
            private_key=private_key,
            output=output,
            provenance=provenance,
            repository=repository,
            commit_sha=commit_sha,
            workflow_ref=workflow_ref,
        )
    except ImportError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.ClickException("EC key signing unavailable") from e


# ===================================================================
# verify  (group — subcommands: sigstore | key)
# ===================================================================
@cli.group(name="verify", subcommand_metavar="PKI_METHOD", cls=_PKICmdGroup)
@click.pass_context
def _verify(ctx: click.Context) -> None:
    """Verify a signed A2A Agent Card.

    Supported PKI methods (subcommands): sigstore (default), key.
    If no method is given, Sigstore verification is used.
    """


@_verify.command(name="sigstore")
@_signed_card_arg
@_identity
@_identity_provider
@_sigstore_staging
@_instance
@_trust_config
@_repository
@_workflow
@click.pass_context
def _verify_sigstore(ctx: click.Context, **kwargs):
    """Verify using Sigstore (DEFAULT).

    Examples:

      sigstore-a2a verify signed-card.json \\
        --identity dev@example.com \\
        --identity_provider https://accounts.google.com
    """
    try:
        from .verify import verify_cmd

        return ctx.invoke(verify_cmd, **kwargs)
    except ImportError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.ClickException("Verification unavailable") from e


@_verify.command(name="key")
@_signed_card_arg
@click.option("--public-key", required=True, type=click.Path(exists=True, path_type=Path), help="PEM EC public key.")
@click.pass_context
def _verify_key(ctx: click.Context, signed_card: Path, public_key: Path):
    """Verify using a public key.

    Examples:

      sigstore-a2a verify key signed-card.json --public-key pubkey.pem
    """
    try:
        from .pki_verify import pki_verify_cmd

        return ctx.invoke(pki_verify_cmd, signed_card=signed_card, public_key=public_key)
    except ImportError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.ClickException("EC key verification unavailable") from e


# ===================================================================
# serve
# ===================================================================
@cli.command("serve")
@_signed_card_arg
@_host
@_port
@_sigstore_staging
@click.option(
    "--public-key", type=click.Path(exists=True, path_type=Path), help="PEM EC public key (EC key verification)."
)
@_no_verify
@_reload
@click.pass_context
def serve_cmd_direct(ctx: click.Context, **kwargs):
    """Serve a signed Agent Card at well-known endpoints.

    Verifies on startup with Sigstore (default) or --public-key for EC key cards.
    """
    try:
        from .serve import serve_cmd

        return ctx.invoke(serve_cmd, **kwargs)
    except ImportError as e:
        console.print(f"[red]Error:[/red] Failed to import serving dependencies: {e}")
        raise click.ClickException("Serving functionality unavailable") from e


# ===================================================================
# trust-instance
# ===================================================================
@cli.command("trust-instance")
@click.argument("root_file", type=click.Path(exists=True, path_type=Path))
@_instance
@click.pass_context
def trust_instance_cmd(ctx: click.Context, root_file: Path, instance: str | None):
    """Bootstrap trust for a Sigstore instance using TUF.

    Examples:

      sigstore-a2a trust-instance root.json --instance https://sigstore.example.com
    """
    from sigstore.models import ClientTrustConfig

    verbose = ctx.obj.get("verbose", False)

    if not instance:
        raise click.ClickException("--instance URL is required for trust-instance")

    try:
        console.print(f"[blue]Bootstrapping trust for: {instance}[/blue]")
        ClientTrustConfig.from_tuf(instance, bootstrap_root=root_file)
        console.print(f"[green]✓[/green] Trust bootstrapped for {instance}")
        if verbose:
            console.print(f"[dim]TUF root: {root_file}[/dim]")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to bootstrap trust: {e}")
        raise click.ClickException(str(e)) from e


# Entrypoint
if __name__ == "__main__":
    cli()
