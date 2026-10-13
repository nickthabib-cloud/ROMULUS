"""Provider-specific transport for ROMULUS's bounded structured model calls."""
from collections.abc import Mapping
from dataclasses import dataclass
import json

from ..config import Settings


@dataclass(frozen=True)
class ProviderResponse:
    text: str
    metadata: dict[str, object]


def model_tool_name(settings: Settings) -> str:
    return "openai.responses" if settings.llm_provider == "openai" else "ollama.api.chat"


def is_model_tool_name(value: object) -> bool:
    return str(value) in {"ollama.api.chat", "openai.responses"}


def configured_model_name(settings: Settings) -> str:
    return settings.openai_model if settings.llm_provider == "openai" else settings.ollama_model


def build_provider(settings: Settings, session):
    if settings.llm_provider == "openai":
        return OpenAIProvider(settings, session)
    return OllamaProvider(settings, session)


class OllamaProvider:
    def __init__(self, settings: Settings, session):
        self.settings = settings
        self.session = session

    def available(self) -> dict:
        try:
            response = self.session.get(
                self.settings.ollama_url + "/api/tags",
                timeout=min(5, self.settings.llm_timeout),
            )
            response.raise_for_status()
            models = [row.get("name") for row in response.json().get("models", [])]
            return {
                "available": True,
                "model_configured": self.settings.ollama_model in models,
                "models": models[:30],
                "provider": "ollama",
            }
        except Exception as exc:
            return {"available": False, "model_configured": False,
                "provider": "ollama", "error": type(exc).__name__}

    def complete(self, system: str, prompt: str, schema: dict, tokens: int) -> ProviderResponse:
        payload = {"model": self.settings.ollama_model, "messages": [
            {"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "stream": True, "think": False, "format": schema,
            "options": {"num_ctx": 32768, "num_predict": tokens, "temperature": 0.15}}
        response = self.session.post(
            self.settings.ollama_url + "/api/chat", json=payload,
            timeout=self.settings.llm_timeout, stream=True,
        )
        response.raise_for_status()
        body = _read_ollama_response(response)
        if body.get("done_reason") == "length":
            raise ValueError("Ollama structured response was truncated at the output limit")
        message = body.get("message", {}) if isinstance(body, Mapping) else {}
        metadata = {
            "provider": "ollama",
            "model": str(body.get("model") or self.settings.ollama_model),
        }
        for source, target in (
            ("prompt_eval_count", "input_tokens"),
            ("eval_count", "output_tokens"),
            ("total_duration", "total_duration_ns"),
        ):
            value = body.get(source)
            if isinstance(value, int) and value >= 0:
                metadata[target] = value
        if "input_tokens" in metadata and "output_tokens" in metadata:
            metadata["total_tokens"] = metadata["input_tokens"] + metadata["output_tokens"]
        return ProviderResponse(str(message.get("content", "")), metadata)

    def complete_text(self, system: str, prompt: str, tokens: int) -> ProviderResponse:
        payload = {"model": self.settings.ollama_model, "messages": [
            {"role": "system", "content": system}, {"role": "user", "content": prompt}],
            "stream": False,
            "options": {"num_ctx": 6144, "temperature": 0.1, "num_predict": tokens}}
        response = self.session.post(
            self.settings.ollama_url + "/api/chat", json=payload,
            timeout=self.settings.llm_timeout,
        )
        response.raise_for_status()
        body = response.json()
        message = body.get("message", {}) if isinstance(body, Mapping) else {}
        return ProviderResponse(str(message.get("content", "")), {
            "provider": "ollama", "model": str(body.get("model") or self.settings.ollama_model)})


class OpenAIProvider:
    def __init__(self, settings: Settings, session):
        self.settings = settings
        self.session = session

    def _configuration_error(self) -> str | None:
        if not self.settings.allow_cloud_llm:
            return "Cloud model use is disabled; set ALLOW_CLOUD_LLM=true to authorize evidence transmission."
        if not self.settings.openai_api_key:
            return "OPENAI_API_KEY is not configured."
        if not self.settings.openai_model:
            return "OPENAI_MODEL is not configured."
        return None

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.settings.openai_api_key}",
            "Content-Type": "application/json"}

    def available(self) -> dict:
        error = self._configuration_error()
        if error:
            return {"available": False, "model_configured": False,
                "provider": "openai", "error": error}
        try:
            response = self.session.get(
                self.settings.openai_base_url + "/models/" + self.settings.openai_model,
                headers=self._headers(), timeout=min(10, self.settings.llm_timeout),
            )
            response.raise_for_status()
            return {"available": True, "model_configured": True,
                "models": [self.settings.openai_model], "provider": "openai"}
        except Exception as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            return {"available": False, "model_configured": False,
                "provider": "openai", "error": type(exc).__name__, "status_code": status}

    def complete(self, system: str, prompt: str, schema: dict, tokens: int) -> ProviderResponse:
        configuration_error = self._configuration_error()
        if configuration_error:
            raise RuntimeError(configuration_error)
        payload = {
            "model": self.settings.openai_model,
            "instructions": system,
            "input": prompt,
            "text": {"format": {"type": "json_schema", "name": "romulus_response",
                "strict": True, "schema": _openai_strict_schema(schema)}},
            "max_output_tokens": tokens,
            "store": False,
        }
        try:
            response = self.session.post(
                self.settings.openai_base_url + "/responses",
                headers=self._headers(), json=payload, timeout=self.settings.llm_timeout,
            )
            response.raise_for_status()
            body = response.json()
        except Exception as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            detail = f" (HTTP {status})" if status is not None else ""
            raise RuntimeError("OpenAI request failed" + detail) from None
        if not isinstance(body, Mapping):
            raise ValueError("OpenAI returned an invalid response object")
        status = str(body.get("status", ""))
        if status != "completed":
            raise ValueError(f"OpenAI structured response was incomplete ({status or 'unknown status'})")
        text = _openai_output_text(body)
        if not text:
            raise ValueError("OpenAI response omitted structured output")
        usage = body.get("usage") if isinstance(body.get("usage"), Mapping) else {}
        metadata = {
            "provider": "openai",
            "model": str(body.get("model") or self.settings.openai_model),
            "request_id": str(body.get("id") or ""),
        }
        for key in ("input_tokens", "output_tokens", "total_tokens"):
            value = usage.get(key)
            if isinstance(value, int) and value >= 0:
                metadata[key] = value
        return ProviderResponse(text, metadata)

    def complete_text(self, system: str, prompt: str, tokens: int) -> ProviderResponse:
        configuration_error = self._configuration_error()
        if configuration_error:
            raise RuntimeError(configuration_error)
        summary_schema = {
            "type": "object",
            "properties": {"summary": {"type": "string", "maxLength": 4000}},
            "required": ["summary"],
            "additionalProperties": False,
        }
        payload = {
            "model": self.settings.openai_model,
            "instructions": system,
            "input": prompt,
            "text": {"format": {
                "type": "json_schema",
                "name": "romulus_summary",
                "strict": True,
                "schema": summary_schema,
            }},
            "max_output_tokens": tokens,
            "store": False,
        }
        try:
            response = self.session.post(
                self.settings.openai_base_url + "/responses",
                headers=self._headers(), json=payload, timeout=self.settings.llm_timeout,
            )
            response.raise_for_status()
            body = response.json()
        except Exception as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            detail = f" (HTTP {status})" if status is not None else ""
            raise RuntimeError("OpenAI request failed" + detail) from None
        if not isinstance(body, Mapping) or str(body.get("status", "")) != "completed":
            raise ValueError("OpenAI text response was incomplete")
        raw_text = _openai_output_text(body)
        try:
            parsed = json.loads(raw_text)
        except (TypeError, json.JSONDecodeError):
            parsed = None
        text = parsed.get("summary") if isinstance(parsed, Mapping) else None
        if not isinstance(text, str):
            raise ValueError("OpenAI response omitted strict summary output")
        usage = body.get("usage") if isinstance(body.get("usage"), Mapping) else {}
        metadata = {"provider": "openai",
            "model": str(body.get("model") or self.settings.openai_model),
            "request_id": str(body.get("id") or "")}
        for key in ("input_tokens", "output_tokens", "total_tokens"):
            value = usage.get(key)
            if isinstance(value, int) and value >= 0:
                metadata[key] = value
        return ProviderResponse(text, metadata)


def _openai_output_text(body: Mapping[str, object]) -> str:
    chunks: list[str] = []
    for output in body.get("output", []) if isinstance(body.get("output"), list) else []:
        if not isinstance(output, Mapping) or output.get("type") != "message":
            continue
        content = output.get("content", [])
        if not isinstance(content, list):
            continue
        for part in content:
            if isinstance(part, Mapping) and part.get("type") == "output_text":
                chunks.append(str(part.get("text", "")))
    return "".join(chunks)


def _openai_strict_schema(value):
    """Copy ROMULUS schemas into OpenAI's strict Structured Outputs subset."""
    if isinstance(value, list):
        return [_openai_strict_schema(item) for item in value]
    if not isinstance(value, Mapping):
        return value
    normalized = {
        key: _openai_strict_schema(item)
        for key, item in value.items()
        # uniqueItems is outside the strict subset. ROMULUS's current anyOf is
        # a parent-object cross-field constraint expressed as partial object
        # fragments, which strict mode also rejects; deterministic admission
        # enforces that same expected-host-or-network rule after parsing.
        if key not in {"uniqueItems", "anyOf"}
    }
    if normalized.get("type") == "object":
        properties = normalized.get("properties")
        if not isinstance(properties, Mapping):
            properties = {}
            normalized["properties"] = properties
        normalized["required"] = list(properties)
        normalized["additionalProperties"] = False
    return normalized


def _read_ollama_response(response) -> dict:
    """Assemble Ollama NDJSON chunks; the read timeout measures stalled inference."""
    iter_lines = getattr(response, "iter_lines", None)
    if not callable(iter_lines):
        return response.json()
    content: list[str] = []
    terminal = None
    truncated = False
    for raw in iter_lines():
        if not raw:
            continue
        if terminal is not None:
            raise ValueError("Ollama streamed data after terminal completion")
        try:
            event = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else str(raw))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Ollama returned malformed streaming JSON") from exc
        if not isinstance(event, dict) or event.get("error"):
            raise ValueError("Ollama returned an invalid streaming event")
        if not isinstance(event.get("done"), bool):
            raise ValueError("Ollama streaming event omitted completion state")
        message = event.get("message", {})
        if isinstance(message, Mapping):
            content.append(str(message.get("content", "")))
        truncated = truncated or event.get("done_reason") == "length"
        if event["done"]:
            terminal = event
    if terminal is None:
        raise ValueError("Ollama stream ended before terminal completion")
    result = dict(terminal)
    if truncated:
        result["done_reason"] = "length"
    message = dict(result.get("message", {})) if isinstance(result.get("message"), Mapping) else {}
    message["content"] = "".join(content)
    result["message"] = message
    return result
