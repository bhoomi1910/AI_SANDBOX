"""AI provider abstraction and the Ollama implementation.

Only ONE provider exists (Ollama) and it only ever talks to a locally hosted
server (OLLAMA_URL). No cloud/paid inference is called anywhere in the system.

Model selection is config-driven and never hard-coded:
  1. OLLAMA_MODEL (settings.ai_model) when set, else
  2. the first installed model reported by GET /api/tags, else
  3. AIUnavailable ("no models installed") — the caller degrades gracefully.

Every network call is bounded by a timeout and maps to AIUnavailable on any
HTTP/transport error, so a missing or broken Ollama never blocks analysis.
"""
from __future__ import annotations

import logging

import httpx

from app.config import get_settings
from app.services.ai.errors import AIUnavailable, AIValidationError

logger = logging.getLogger(__name__)

_AI_URL_DEFAULT = "http://localhost:11434"


class AIProvider:
    """Contract every provider implements (currently only Ollama)."""

    name = "generic"

    def label(self) -> str:
        raise NotImplementedError

    def list_models(self) -> list[str]:
        raise NotImplementedError

    def select_model(self) -> str:
        raise NotImplementedError

    def generate(self, prompt: str, model: str) -> str:
        raise NotImplementedError


class OllamaProvider(AIProvider):
    """Talks to a local Ollama server over its REST API."""

    name = "ollama"

    def __init__(self, url: str | None = None, model: str | None = None,
                 timeout: float | None = None, probe_timeout: float | None = None,
                 client: httpx.Client | None = None) -> None:
        settings = get_settings()
        self.url = (url or settings.ollama_url or _AI_URL_DEFAULT).rstrip("/")
        self.model = settings.ai_model if model is None else (model or "")
        self.timeout = timeout if timeout is not None else settings.ai_timeout_seconds
        self.probe_timeout = probe_timeout if probe_timeout is not None else settings.ai_probe_timeout_seconds
        self._selected: str | None = None
        self._client = client or httpx.Client(base_url=self.url, timeout=self.timeout)

    def label(self) -> str:
        model = self._selected or self.model or "auto"
        return f"ollama/{model}"

    def list_models(self) -> list[str]:
        try:
            resp = self._client.get("/api/tags", timeout=self.probe_timeout)
            resp.raise_for_status()
            names = [m.get("name", "") for m in resp.json().get("models", [])]
            return sorted(n for n in names if n)
        except (httpx.HTTPError, ValueError) as exc:
            raise AIUnavailable(f"cannot reach Ollama at {self.url}: {exc}") from exc

    def select_model(self) -> str:
        if self.model:
            return self.model
        installed = self.list_models()
        if not installed:
            raise AIUnavailable("Ollama is reachable but has no models installed")
        self._selected = installed[0]
        logger.info("Auto-selected Ollama model: %s", self._selected)
        return self._selected

    def generate(self, prompt: str, model: str) -> str:
        body = {"model": model, "prompt": prompt, "stream": False}
        try:
            resp = self._client.post("/api/generate", json={**body, "format": "json"})
            if resp.status_code == 404:
                raise AIUnavailable(f"model '{model}' is not installed on Ollama")
            if resp.status_code >= 400:
                # Older Ollama servers reject "format": retry without it.
                resp = self._client.post("/api/generate", json=body)
            resp.raise_for_status()
            text = resp.json().get("response", "")
            if not text.strip():
                raise AIValidationError("Ollama returned an empty response")
            return text
        except httpx.HTTPError as exc:
            raise AIUnavailable(f"Ollama generate failed: {exc}") from exc
        except ValueError as exc:
            raise AIValidationError(f"Ollama returned a non-JSON response: {exc}") from exc


_PROVIDER: AIProvider | None = None


def get_provider() -> AIProvider:
    """Process-wide provider singleton.

    Tests replace this function (monkeypatch app.services.ai.get_provider) or
    construct an OllamaProvider with a mocked httpx.Client.
    """
    global _PROVIDER
    if _PROVIDER is None:
        _PROVIDER = OllamaProvider()
    return _PROVIDER
