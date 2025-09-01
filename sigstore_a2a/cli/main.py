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

from pathlib import Path

import click
from rich.console import Console

import sigstore_a2a

console = Console()


# Common trust / instance toggles
_sigstore_staging = click.option(
    "--staging",
    type=bool,
    is_flag=True,
    help="Use Sigstore staging environment.",
)
_trust_config = click.option(
    "--trust_config",
    type=click.Path(path_type=Path),
    help="Client trust configuration to use.",
)

# Signing inputs / outputs
_agent_card_arg = click.argument("agent_card", type=click.Path(exists=True, path_type=Path))
_signed_card_arg = click.argument("signed_card", type=click.Path(exists=True, path_type=Path))
_output = click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output path for the signed Agent Card.",
)
_provenance = click.option(
    "--provenance",
    is_flag=True,
    default=False,
    type=bool,
    help="Include SLSA provenance generation.",
)

# OIDC / OAuth
_identity_token = click.option(
    "--identity_token",
    type=str,
    metavar="TOKEN",
    help="Use a fixed OIDC identity token instead of an OAuth flow.",
)
_client_id = click.option(
    "--client_id",
    type=str,
    metavar="ID",
    help="Custom OpenID Connect client ID to use during OAuth2.",
)
_client_secret = click.option(
    "--client_secret",
    type=str,
    metavar="SECRET",
    help="Custom OpenID Connect client secret to use during OAuth2.",
)
_use_ambient_credentials = click.option(
    "--use_ambient_credentials",
    type=bool,
    is_flag=True,
    help="Use credentials from the ambient environment.",
)

# Provenance overrides
_repository = click.option("--repository", help="Override/require repository.")
_commit_sha = click.option("--commit_sha", help="Override commit SHA.")
_workflow_ref = click.option("--workflow_ref", help="Override workflow reference.")

# Verification constraints
_identity = click.option(
    "--identity",
    type=str,
    metavar="IDENTITY",
    help="Expected identity of the signer (e.g., name@example.com).",
)
_identity_provider = click.option(
    "--identity_provider",
    type=str,
    metavar="IDENTITY_PROVIDER",
    required=True,
    help="Expected identity provider (e.g., https://accounts.example.com).",
)
_workflow = click.option("--workflow", help="Required workflow name constraint.")

# Serve options
_host = click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind to.")
_port = click.option("--port", default=8080, type=int, show_default=True, help="Port to bind to.")
_no_verify = click.option("--no-verify", is_flag=True, help="Skip signature verification on startup.")
_reload = click.option("--reload", is_flag=True, help="Enable auto-reload for development.")


# CLI root
@click.group(
    context_settings=dict(help_option_names=["-h", "--help"]),
    epilog=("Check https://sigstore.github.io/sigstore-a2a for documentation and more details."),
)
@click.version_option(sigstore_a2a.__version__, "--version")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """sigstore-a2a command line."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


# sign
@cli.command("sign")
@_use_ambient_credentials
@_agent_card_arg
@_output
@_sigstore_staging
@_trust_config
@_provenance
@_identity_token
@_client_id
@_client_secret
@_repository
@_commit_sha
@_workflow_ref
@click.pass_context
def sign_cmd_direct(ctx: click.Context, **kwargs):
    """Sign an Agent Card and embed a Sigstore bundle."""
    try:
        from .sign import sign_cmd

        return ctx.invoke(sign_cmd, **kwargs)
    except ImportError as e:
        console.print(f"[red]Error:[/red] Failed to import signing dependencies: {e}")


# verify
@cli.command("verify")
@_signed_card_arg
@_identity
@_identity_provider
@_sigstore_staging
@_trust_config
@_repository
@_workflow
@click.pass_context
def verify_cmd_direct(ctx: click.Context, **kwargs):
    """Verify a signed Agent Card."""
    try:
        from .verify import verify_cmd

        return ctx.invoke(verify_cmd, **kwargs)
    except ImportError as e:
        console.print(f"[red]Error:[/red] Failed to import verification dependencies: {e}")
        raise click.ClickException("Verification functionality unavailable") from e


# serve
@cli.command("serve")
@_signed_card_arg
@_host
@_port
@_sigstore_staging
@_no_verify
@_reload
@click.pass_context
def serve_cmd_direct(ctx: click.Context, **kwargs):
    """
    Serve a signed Agent Card at well-known endpoints.

    For demo/testing only; this does not implement a real Agent.
    """
    try:
        from .serve import serve_cmd

        return ctx.invoke(serve_cmd, **kwargs)
    except ImportError as e:
        console.print(f"[red]Error:[/red] Failed to import serving dependencies: {e}")
        raise click.ClickException("Serving functionality unavailable") from e


# Entrypoint
if __name__ == "__main__":
    cli()
