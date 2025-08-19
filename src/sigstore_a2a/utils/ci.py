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

import os
from typing import Any


def detect_ci_environment() -> str | None:
    """Detect the current CI/CD environment.

    Returns:
        Name of CI/CD provider or None if not detected
    """
    if os.getenv("GITHUB_ACTIONS"):
        return "github-actions"
    elif os.getenv("GITLAB_CI"):
        return "gitlab-ci"
    else:
        return None


def get_github_context() -> dict[str, Any]:
    """Extract GitHub Actions context from environment variables.

    Returns:
        Dictionary containing GitHub Actions context
    """
    context = {}

    # Repository information
    if repo := os.getenv("GITHUB_REPOSITORY"):
        context["repository"] = repo
        context["repository_owner"] = repo.split("/")[0]
        context["repository_name"] = repo.split("/")[1]

    # Commit information
    if sha := os.getenv("GITHUB_SHA"):
        context["commit_sha"] = sha

    if ref := os.getenv("GITHUB_REF"):
        context["ref"] = ref
        if ref.startswith("refs/heads/"):
            context["branch"] = ref[11:]
        elif ref.startswith("refs/tags/"):
            context["tag"] = ref[10:]

    # Workflow information
    if workflow := os.getenv("GITHUB_WORKFLOW"):
        context["workflow_name"] = workflow

    if run_id := os.getenv("GITHUB_RUN_ID"):
        context["run_id"] = run_id

    if run_number := os.getenv("GITHUB_RUN_NUMBER"):
        context["run_number"] = run_number

    if run_attempt := os.getenv("GITHUB_RUN_ATTEMPT"):
        context["run_attempt"] = run_attempt

    # Actor information
    if actor := os.getenv("GITHUB_ACTOR"):
        context["actor"] = actor

    # Event information
    if event_name := os.getenv("GITHUB_EVENT_NAME"):
        context["event_name"] = event_name

    if event_path := os.getenv("GITHUB_EVENT_PATH"):
        context["event_path"] = event_path

    # Server URL
    if server_url := os.getenv("GITHUB_SERVER_URL"):
        context["server_url"] = server_url

    # API URL
    if api_url := os.getenv("GITHUB_API_URL"):
        context["api_url"] = api_url

    # Job information
    if job := os.getenv("GITHUB_JOB"):
        context["job"] = job

    return context


def get_ci_context() -> dict[str, Any]:
    """Get CI/CD context based on detected environment.

    Returns:
        Dictionary containing CI/CD context
    """
    ci_env = detect_ci_environment()

    if ci_env == "github-actions":
        return {"ci_provider": ci_env, **get_github_context()}
    else:
        return {"ci_provider": ci_env}
