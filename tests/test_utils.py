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
from unittest.mock import patch

import pytest

from sigstore_a2a.utils.ci import detect_ci_environment, get_ci_context, get_github_context
from sigstore_a2a.utils.crypto import canonicalize_json, compute_digest, verify_digest


class TestCrypto:
    """Test cryptographic utilities."""

    def test_compute_digest_sha256(self):
        """Test SHA-256 digest computation."""
        data = b"hello world"
        digest = compute_digest(data, "sha256")
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert digest == expected

    def test_compute_digest_sha1(self):
        """Test SHA-1 digest computation."""
        data = b"hello world"
        digest = compute_digest(data, "sha1")
        expected = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
        assert digest == expected

    def test_compute_digest_unsupported(self):
        """Test unsupported digest algorithm."""
        data = b"hello world"
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            compute_digest(data, "md5")

    def test_verify_digest_valid(self):
        """Test digest verification with valid digest."""
        data = b"hello world"
        digest = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert verify_digest(data, digest, "sha256") is True

    def test_verify_digest_invalid(self):
        """Test digest verification with invalid digest."""
        data = b"hello world"
        digest = "invalid_digest"
        assert verify_digest(data, digest, "sha256") is False

    def test_canonicalize_json(self):
        """Test JSON canonicalization."""
        obj = {"b": 2, "a": 1, "c": {"z": 3, "x": 4}}
        canonical = canonicalize_json(obj)
        expected = '{"a":1,"b":2,"c":{"x":4,"z":3}}'
        assert canonical.decode() == expected


class TestCI:
    """Test CI/CD environment detection."""

    def test_detect_ci_environment_github(self):
        """Test GitHub Actions detection."""
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            assert detect_ci_environment() == "github-actions"

    def test_detect_ci_environment_gitlab(self):
        """Test GitLab CI detection."""
        with patch.dict(os.environ, {"GITLAB_CI": "true"}, clear=True):
            assert detect_ci_environment() == "gitlab-ci"

    def test_detect_ci_environment_none(self):
        """Test no CI environment detected."""
        with patch.dict(os.environ, {}, clear=True):
            assert detect_ci_environment() is None

    def test_get_github_context(self):
        """Test GitHub context extraction."""
        env_vars = {
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_SHA": "abc123",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW": "CI",
            "GITHUB_RUN_ID": "123456",
            "GITHUB_ACTOR": "testuser",
        }

        with patch.dict(os.environ, env_vars):
            context = get_github_context()

            assert context["repository"] == "owner/repo"
            assert context["repository_owner"] == "owner"
            assert context["repository_name"] == "repo"
            assert context["commit_sha"] == "abc123"
            assert context["branch"] == "main"
            assert context["workflow_name"] == "CI"
            assert context["run_id"] == "123456"
            assert context["actor"] == "testuser"

    def test_get_ci_context_github(self):
        """Test CI context for GitHub Actions."""
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "owner/repo"}):
            context = get_ci_context()
            assert context["ci_provider"] == "github-actions"
            assert context["repository"] == "owner/repo"

    def test_get_ci_context_unknown(self):
        """Test CI context for unknown environment."""
        with patch.dict(os.environ, {}, clear=True):
            context = get_ci_context()
            assert context["ci_provider"] is None
