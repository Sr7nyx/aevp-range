"""Model provider interface.

  ScriptedProvider          deterministic mock; proves the pipeline offline.
  OpenAICompatibleProvider  OpenAI /chat/completions (OpenRouter, Groq, Cerebras).
  AnthropicMessagesProvider Anthropic /v1/messages (AI Hub and other Anthropic
                            drop-ins). The agent speaks OpenAI-shaped messages
                            internally; this provider translates them on the way
                            out and the Anthropic response back to an Action.

All live providers share a RateLimiter, Retry-After-aware backoff, and a browser
User-Agent (urllib's default trips Cloudflare 1010). `OpenRouterProvider` is kept
as an alias.
"""
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional, Union

from .budget import Budget

_DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    call_id: str = "call_0"


@dataclass
class Finish:
    text: str


Action = Union[ToolCall, Finish]


class RateLimiter:
    """Client-side pacing shared across every trial in a campaign."""

    def __init__(self, rpm: float = 0.0) -> None:
        self.min_interval = 60.0 / rpm if rpm and rpm > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        delta = self._last + self.min_interval - time.monotonic()
        if delta > 0:
            time.sleep(delta)
        self._last = time.monotonic()


def _parse_retry_after(headers, fallback: float) -> float:
    ra = headers.get("Retry-After") if headers else None
    if ra:
        try:
            return min(float(ra), 120.0)
        except (TypeError, ValueError):
            pass
    return fallback


def http_post_json(url: str, headers: dict, body: dict, *, timeout: int,
                   max_retries: int, limiter: Optional[RateLimiter]) -> dict:
    """Shared POST-with-retry. Honors Retry-After on 429/5xx; retries transient
    network errors; raises RuntimeError('HTTP <code>: <body>') otherwise."""
    data = json.dumps(body).encode("utf-8")
    last_err = None
    for attempt in range(max_retries):
        if limiter is not None:
            limiter.wait()
        req = urllib.request.Request(url, data=data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            last_err = RuntimeError(f"HTTP {exc.code}: {detail}")
            if exc.code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                time.sleep(_parse_retry_after(exc.headers, 2.0 ** attempt))
                continue
            raise last_err from exc
        except Exception as exc:
            last_err = exc
            if attempt < max_retries - 1:
                time.sleep(2.0 ** attempt)
                continue
            raise
    raise RuntimeError(f"provider failed after {max_retries} attempts: {last_err}")


class Provider:
    def next_action(self, messages: list[dict], tools: list[dict]) -> Action:
        raise NotImplementedError

    def fingerprint(self) -> dict:
        return {"provider": "abstract"}


class ScriptedProvider(Provider):
    def __init__(self, actions: list[Action], final_text: str = "Done.") -> None:
        self._actions = list(actions)
        self._final_text = final_text
        self._i = 0

    def next_action(self, messages, tools) -> Action:
        if self._i < len(self._actions):
            act = self._actions[self._i]
            self._i += 1
            if isinstance(act, ToolCall):
                act.call_id = f"call_{self._i}"
            return act
        return Finish(self._final_text)

    def fingerprint(self) -> dict:
        return {"provider": "scripted", "model": "mock", "deterministic": True}


@dataclass
class OpenAICompatibleProvider(Provider):
    model: str
    api_key: str
    base_url: str = "https://openrouter.ai/api/v1"
    temperature: float = 0.0
    top_p: float = 1.0
    max_tokens: int = 1024
    reasoning_effort: Optional[str] = None
    # Merged into the request body. Used to pin an aggregator's upstream, e.g.
    # OpenRouter {"provider": {"order": ["Cerebras"], "allow_fallbacks": false}}.
    extra_body: Optional[dict] = None
    user_agent: str = _DEFAULT_UA
    timeout: int = 90
    max_retries: int = 4
    budget: Optional[Budget] = None
    limiter: Optional[RateLimiter] = None
    _server_fingerprint: Optional[str] = field(default=None, init=False, repr=False)
    _served_by: Optional[str] = field(default=None, init=False, repr=False)

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "HTTP-Referer": "https://github.com/aevp/range",
            "X-Title": "AEVP Range",
        }

    def next_action(self, messages, tools) -> Action:
        payload = {
            "model": self.model, "messages": messages,
            "temperature": self.temperature, "top_p": self.top_p,
            "max_tokens": self.max_tokens,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        if self.reasoning_effort:
            payload["reasoning_effort"] = self.reasoning_effort
        if self.extra_body:
            payload.update(self.extra_body)

        resp = http_post_json(f"{self.base_url.rstrip('/')}/chat/completions",
                              self._headers(), payload, timeout=self.timeout,
                              max_retries=self.max_retries, limiter=self.limiter)

        usage = resp.get("usage") or {}
        if self.budget is not None:
            self.budget.charge(prompt_tokens=int(usage.get("prompt_tokens") or 0),
                               completion_tokens=int(usage.get("completion_tokens") or 0))
        if resp.get("system_fingerprint"):
            self._server_fingerprint = resp["system_fingerprint"]
        # Aggregators report which upstream served the call; record it so a run
        # can show it was not silently spread across different backends.
        if resp.get("provider"):
            self._served_by = str(resp["provider"])

        choices = resp.get("choices") or []
        if not choices:
            return Finish("")
        message = choices[0].get("message") or {}
        calls = message.get("tool_calls") or []
        if calls:
            call = calls[0]
            fn = call.get("function") or {}
            raw = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except json.JSONDecodeError:
                args = {}
            return ToolCall(fn.get("name") or "", args, call.get("id") or "call_0")
        return Finish(message.get("content") or "")

    def fingerprint(self) -> dict:
        return {"provider": "openai-compatible", "base_url": self.base_url,
                "model": self.model, "temperature": self.temperature, "top_p": self.top_p,
                "max_tokens": self.max_tokens, "reasoning_effort": self.reasoning_effort,
                "extra_body": self.extra_body, "served_by": self._served_by,
                "system_fingerprint": self._server_fingerprint}


# --------------------------------------------------------------------------- #
# Anthropic Messages translation (standalone + unit-testable)
# --------------------------------------------------------------------------- #
def openai_to_anthropic(messages: list[dict], tools: list[dict]):
    """Translate the agent's OpenAI-shaped messages/tools to the Anthropic
    Messages format. Returns (system, messages, tools)."""
    system_parts, anth = [], []
    for m in messages:
        role = m.get("role")
        if role == "system":
            if m.get("content"):
                system_parts.append(m["content"])
        elif role == "user":
            anth.append({"role": "user", "content": m.get("content") or ""})
        elif role == "assistant":
            tcs = m.get("tool_calls")
            if tcs:
                blocks = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in tcs:
                    fn = tc.get("function") or {}
                    raw = fn.get("arguments")
                    if isinstance(raw, str):
                        try:
                            raw = json.loads(raw or "{}")
                        except json.JSONDecodeError:
                            raw = {}
                    blocks.append({"type": "tool_use", "id": tc.get("id", "toolu_0"),
                                   "name": fn.get("name", ""), "input": raw or {}})
                anth.append({"role": "assistant", "content": blocks})
            else:
                anth.append({"role": "assistant", "content": m.get("content") or ""})
        elif role == "tool":
            anth.append({"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": m.get("tool_call_id", ""),
                "content": m.get("content") or ""}]})
    anth_tools = None
    if tools:
        anth_tools = [{
            "name": (t.get("function") or {}).get("name", ""),
            "description": (t.get("function") or {}).get("description", ""),
            "input_schema": (t.get("function") or {}).get("parameters")
                            or {"type": "object", "properties": {}},
        } for t in tools]
    return "\n\n".join(system_parts), anth, anth_tools


def anthropic_to_action(resp: dict) -> Action:
    content = resp.get("content") or []
    for block in content:
        if block.get("type") == "tool_use":
            return ToolCall(block.get("name", ""), block.get("input") or {},
                            block.get("id", "toolu_0"))
    texts = [b.get("text", "") for b in content if b.get("type") == "text"]
    return Finish("\n".join(texts))


@dataclass
class AnthropicMessagesProvider(Provider):
    model: str
    api_key: str
    base_url: str = "https://ai-hub.aicampus.my/v1"
    temperature: float = 0.7
    max_tokens: int = 1024
    anthropic_version: str = "2023-06-01"
    user_agent: str = _DEFAULT_UA
    timeout: int = 90
    max_retries: int = 4
    budget: Optional[Budget] = None
    limiter: Optional[RateLimiter] = None

    def _headers(self) -> dict:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": self.anthropic_version,
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }

    def next_action(self, messages, tools) -> Action:
        system, anth_messages, anth_tools = openai_to_anthropic(messages, tools)
        payload = {"model": self.model, "max_tokens": self.max_tokens,
                   "temperature": self.temperature, "messages": anth_messages}
        if system:
            payload["system"] = system
        if anth_tools:
            payload["tools"] = anth_tools

        resp = http_post_json(f"{self.base_url.rstrip('/')}/messages",
                              self._headers(), payload, timeout=self.timeout,
                              max_retries=self.max_retries, limiter=self.limiter)

        usage = resp.get("usage") or {}
        if self.budget is not None:
            self.budget.charge(prompt_tokens=int(usage.get("input_tokens") or 0),
                               completion_tokens=int(usage.get("output_tokens") or 0))
        return anthropic_to_action(resp)

    def fingerprint(self) -> dict:
        return {"provider": "anthropic-messages", "base_url": self.base_url,
                "model": self.model, "temperature": self.temperature,
                "max_tokens": self.max_tokens, "anthropic_version": self.anthropic_version,
                "system_fingerprint": None}


OpenRouterProvider = OpenAICompatibleProvider
