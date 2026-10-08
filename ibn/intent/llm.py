"""LLM providers. Gemini is the default; any provider implementing `LLMProvider` can be swapped in."""

from __future__ import annotations

import json
import time
from typing import Any, Protocol

import requests


class LLMError(Exception):
    pass


class LLMProvider(Protocol):
    def generate_json(self, system: str, messages: list[dict[str, str]]) -> dict[str, Any]:
        """messages: [{"role": "user"|"model", "text": ...}] -> parsed JSON object."""
        ...


class GeminiProvider:
    URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    RETRY_STATUS = {429, 500, 502, 503, 504}

    def __init__(self, api_key: str, model: str, timeout: float = 60.0, retries: int = 4):
        if not api_key:
            raise LLMError("GEMINI_API_KEY is not set (export it or put it in .env)")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.retries = retries

    def generate_json(self, system: str, messages: list[dict[str, str]]) -> dict[str, Any]:
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": m["role"], "parts": [{"text": m["text"]}]} for m in messages],
            "generationConfig": {"responseMimeType": "application/json", "temperature": 0},
        }
        for attempt in range(self.retries + 1):
            try:
                resp = requests.post(self.URL.format(model=self.model), json=body, timeout=self.timeout,
                                     headers={"x-goog-api-key": self.api_key})
            except requests.RequestException as exc:
                if attempt == self.retries:
                    raise LLMError(f"Gemini request failed: {exc}") from exc
            else:
                if resp.status_code not in self.RETRY_STATUS or attempt == self.retries:
                    break
            time.sleep(2 ** (attempt + 1))  # 2s, 4s, 8s, 16s
        if resp.status_code != 200:
            raise LLMError(f"Gemini returned HTTP {resp.status_code}: {resp.text[:300]}")
        try:
            text = "".join(p.get("text", "") for p in resp.json()["candidates"][0]["content"]["parts"])
            return json.loads(text)
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise LLMError(f"unexpected Gemini response: {resp.text[:300]}") from exc
