"""Thin OpenAI-compatible chat client (DeepSeek) with JSON response parsing."""

import json
import time
from typing import Any, Dict, List, Optional

import httpx

from ..config import Settings, get_settings

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, settings: Settings = None) -> None:
        self.settings = settings or get_settings()
        if not self.settings.openai_api_key:
            raise LLMError("LLM API key is not configured")
        self.base_url = self.settings.openai_base_url.rstrip("/")
        self.model = self.settings.openai_model

    def chat_json(
        self,
        system: str,
        user: str,
        max_tokens: int = 4096,
        temperature: float = 0.1,
        retries: int = 2,
        timeout: float = 180.0,
    ) -> Any:
        """Chat completion that must return a JSON object. Returns parsed JSON."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "response_format": {"type": "json_object"},
        }
        headers = {
            "Authorization": f"Bearer {self.settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}/chat/completions"

        last_error: Optional[str] = None
        for attempt in range(retries + 1):
            try:
                response = httpx.post(url, json=payload, headers=headers, timeout=timeout)
                if response.status_code in RETRYABLE_STATUS and attempt < retries:
                    time.sleep(2.0 * (attempt + 1))
                    continue
                if response.status_code != 200:
                    raise LLMError(f"LLM API returned {response.status_code}: {response.text[:300]}")
                data = response.json()
                content = data["choices"][0]["message"]["content"] or ""
                return _parse_json_object(content)
            except httpx.HTTPError as exc:
                last_error = str(exc)
                if attempt < retries:
                    time.sleep(2.0 * (attempt + 1))
                    continue
                raise LLMError(f"LLM request failed: {last_error}") from exc
        raise LLMError(f"LLM request failed after retries: {last_error}")


def _parse_json_object(content: str) -> Any:
    """Parse JSON possibly wrapped in markdown fences."""
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    try:
        return json.loads(text)
    except ValueError as exc:
        # Try to recover the first {...} block.
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except ValueError:
                pass
        raise LLMError(f"LLM returned invalid JSON: {content[:300]}") from exc
