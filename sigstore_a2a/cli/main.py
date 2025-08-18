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

console = Console()


@click.group()
@click.version_option(version="0.4.0", prog_name="sigstore-a2a")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@cli.command("sign")
@click.argument("agent_card", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output path for signed Agent Card")
@click.option("--staging", is_flag=True, help="Use Sigstore staging environment")
@click.option("--trust_config", type=click.Path(path_type=Path), help="The client trust configuration to use")
@click.option("--no-provenance", is_flag=True, help="Skip SLSA provenance generation")
@click.option("--repository", help="Override repository for provenance")
@click.option("--commit-sha", help="Override commit SHA for provenance")
@click.option("--workflow-ref", help="Override workflow reference for provenance")
@click.pass_context
def sign_cmd_direct(ctx: click.Context, **kwargs):
    try:
        from .sign import sign_cmd

        return ctx.invoke(sign_cmd, **kwargs)
    except ImportError as e:
        console.print(f"[red]Error:[/red] Failed to import signing dependencies: {e}")


@cli.command("verify")
@click.argument("signed_card", type=click.Path(exists=True, path_type=Path))
@click.option("--staging", is_flag=True, help="Use Sigstore staging environment")
@click.option("--trust_config", type=click.Path(path_type=Path), help="The client trust configuration to use")
@click.option("--repository", help="Required repository constraint")
@click.option("--workflow", help="Required workflow name constraint")
@click.option("--actor", help="Required actor/user constraint")
@click.option("--issuer", help="Required OIDC issuer constraint")
@click.pass_context
def verify_cmd_direct(ctx: click.Context, **kwargs):
    """Verify a Card."""
    try:
        from .verify import verify_cmd

        return ctx.invoke(verify_cmd, **kwargs)
    except ImportError as e:
        console.print(f"[red]Error:[/red] Failed to import verification dependencies: {e}")
        raise click.ClickException("Verification functionality unavailable") from e


@cli.command("serve")
@click.argument("signed_card", type=click.Path(exists=True, path_type=Path))
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8080, help="Port to bind to")
@click.option("--staging", is_flag=True, help="Use Sigstore staging environment")
@click.option("--no-verify", is_flag=True, help="Skip signature verification on startup")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
@click.pass_context
def serve_cmd_direct(ctx: click.Context, **kwargs):
    """
    Serve a signed AgentCard at well-known endpoints.
    This is just for demonstration purposes, testing etc. Obviously we have no
    intention of this being an Agent.
    """
    try:
        from .serve import serve_cmd

        return ctx.invoke(serve_cmd, **kwargs)
    except ImportError as e:
        console.print(f"[red]Error:[/red] Failed to import serving dependencies: {e}")
        raise click.ClickException("Serving functionality unavailable") from e


if __name__ == "__main__":
    cli()
