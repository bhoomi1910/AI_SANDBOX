"""Ollama provider: REST contract, model selection, graceful failure mapping."""
import httpx
import pytest

from app.services.ai.errors import AIUnavailable, AIValidationError
from app.services.ai.providers import OllamaProvider


def _provider(handler, model="m1"):
    client = httpx.Client(transport=httpx.MockTransport(handler), base_url="http://localhost:11434")
    return OllamaProvider(url="http://localhost:11434", model=model,
                          timeout=2.0, probe_timeout=1.0, client=client)


def test_generate_posts_format_json_and_returns_text():
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode()
        assert '"format":"json"' in body
        assert '"stream":false' in body
        return httpx.Response(200, json={"response": '{"executive_summary": "ok"}'})

    provider = _provider(handler)
    assert provider.generate("prompt", "m1") == '{"executive_summary": "ok"}'


def test_generate_retries_without_format_on_400():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if len(calls) == 1:
            return httpx.Response(400, json={"error": "format not supported"})
        return httpx.Response(200, json={"response": "{}"})

    provider = _provider(handler)
    assert provider.generate("p", "m1") == "{}"
    assert calls == ["/api/generate", "/api/generate"]


def test_generate_404_model_missing_is_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "model 'm1' not found"})

    with pytest.raises(AIUnavailable):
        _provider(handler).generate("p", "m1")


def test_generate_transport_error_is_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(AIUnavailable):
        _provider(handler).generate("p", "m1")


def test_generate_empty_response_is_validation_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": ""})

    with pytest.raises(AIValidationError):
        _provider(handler).generate("p", "m1")


def test_select_model_uses_configured_model_without_calling_server():
    called = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(request.url.path)
        return httpx.Response(200, json={"models": [{"name": "unused"}]})

    provider = _provider(handler, model="qwen3:4b")
    assert provider.select_model() == "qwen3:4b"
    assert called == []  # no /api/tags call when a model is configured


def test_select_model_auto_detects_first_installed_model():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json={"models": [{"name": "zebra"}, {"name": "alpha"}]})

    provider = _provider(handler, model="")
    assert provider.select_model() == "alpha"
    assert provider.label() == "ollama/alpha"


def test_select_model_with_no_models_is_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"models": []})

    with pytest.raises(AIUnavailable):
        _provider(handler, model="").select_model()


def test_list_models_unreachable_is_unavailable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(AIUnavailable):
        _provider(handler).list_models()
