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
from contextlib import asynccontextmanager
from pathlib import Path

import click
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from rich.console import Console

from ..models.signature import SignedAgentCard
from ..verifier import AgentCardVerifier

console = Console()


def create_app(signed_card_path: Path, verify_on_serve: bool = True, staging: bool = False) -> FastAPI:
    """Create FastAPI app for serving Agent Card.

    Args:
        signed_card_path: Path to signed Agent Card
        verify_on_serve: Whether to verify signature on startup
        staging: Use staging Sigstore environment

    Returns:
        FastAPI application
    """
    # Shared state
    app_state = {"signed_card_data": None, "agent_card_data": None}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            with open(signed_card_path) as f:
                app_state["signed_card_data"] = json.load(f)

            signed_card = SignedAgentCard.model_validate(app_state["signed_card_data"])
            app_state["agent_card_data"] = signed_card.agent_card.model_dump(by_alias=True, mode="json")

            if verify_on_serve:
                verifier = AgentCardVerifier(
                    identity=None,
                    oidc_issuer=None,
                    staging=staging,
                )
                result = verifier.verify_signed_card(signed_card)

                if not result.valid:
                    raise ValueError(f"Signature verification failed: {result.errors}")

                console.print("[green]✓[/green] Agent Card signature verified")

            console.print(f"[blue]Serving Agent Card: {signed_card.agent_card.name}[/blue]")

        except Exception as e:
            console.print(f"[red]✗[/red] Failed to load Agent Card: {e}")
            raise

        yield

        console.print("[blue]Shutting down Agent Card server[/blue]")

    app = FastAPI(
        title="A2A Agent Card Server",
        description="Serves signed A2A Agent Cards at well-known endpoints",
        version="0.4.0",
        lifespan=lifespan,
    )

    @app.get("/.well-known/agent.json")
    async def get_agent_card():
        """Serve the Agent Card at the well-known endpoint."""
        if app_state["agent_card_data"] is None:
            raise HTTPException(status_code=503, detail="Agent Card not loaded")

        return JSONResponse(content=app_state["agent_card_data"])

    @app.get("/.well-known/agent.signed.json")
    async def get_signed_agent_card():
        """Serve the complete signed Agent Card with verification material."""
        if app_state["signed_card_data"] is None:
            raise HTTPException(status_code=503, detail="Signed Agent Card not loaded")

        return JSONResponse(content=app_state["signed_card_data"])

    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "agent_loaded": app_state["signed_card_data"] is not None}

    @app.get("/")
    async def root():
        """Root endpoint with API information."""
        if app_state["agent_card_data"]:
            return {
                "message": "A2A Agent Card Server",
                "agent": {
                    "name": app_state["agent_card_data"].get("name"),
                    "version": app_state["agent_card_data"].get("version"),
                    "url": app_state["agent_card_data"].get("url"),
                },
                "endpoints": {
                    "agent_card": "/.well-known/agent.json",
                    "signed_agent_card": "/.well-known/agent.signed.json",
                    "health": "/health",
                },
            }
        else:
            return {"message": "A2A Agent Card Server", "status": "loading"}

    return app


@click.command("serve")
@click.argument("signed_card", type=click.Path(exists=True, path_type=Path))
@click.option("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")
@click.option("--port", default=8080, help="Port to bind to (default: 8080)")
@click.option("--staging", is_flag=True, help="Use Sigstore staging environment for verification")
@click.option("--no-verify", is_flag=True, help="Skip signature verification on startup")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
@click.pass_context
def serve_cmd(
    ctx: click.Context, signed_card: Path, host: str, port: int, staging: bool, no_verify: bool, reload: bool
) -> None:
    """Serve a signed Agent Card at well-known endpoints.

    This command starts an HTTP server that serves the Agent Card at the
    standard A2A discovery endpoint (/.well-known/agent.json) and provides
    the complete signed card with verification material at
    /.well-known/agent.signed.json.

    Examples:
        sigstore-a2a serve signed-card.json
        sigstore-a2a serve signed-card.json --host 0.0.0.0 --port 8080
        sigstore-a2a serve signed-card.json --no-verify
    """
    verbose = ctx.obj.get("verbose", False)

    if verbose:
        console.print(f"[blue]Starting server for: {signed_card}[/blue]")
        console.print(f"[blue]Host: {host}[/blue]")
        console.print(f"[blue]Port: {port}[/blue]")
        if no_verify:
            console.print("[yellow]Signature verification disabled[/yellow]")

    try:
        app = create_app(signed_card_path=signed_card, verify_on_serve=not no_verify, staging=staging)

        console.print(f"[green]Starting server at http://{host}:{port}[/green]")
        console.print(f"[blue]Agent Card endpoint: http://{host}:{port}/.well-known/agent.json[/blue]")
        console.print(f"[blue]Signed card endpoint: http://{host}:{port}/.well-known/agent.signed.json[/blue]")
        console.print("[dim]Press Ctrl+C to stop[/dim]")

        if reload:
            console.print("[yellow]Warning: reload mode not supported with custom app configuration[/yellow]")
            reload = False
        uvicorn.run(app, host=host, port=port, log_level="info" if verbose else "warning")

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to start server: {e}")
        if verbose:
            console.print_exception()
        raise click.ClickException(str(e)) from e
