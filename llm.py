import os
import time
import tiktoken
from openai import OpenAI
from typing import List, Dict, Any

from constants import MODEL_NAME, MAX_TOKENS, TEMPERATURE, MAX_HISTORY_CHARS


class APIUnavailableError(Exception):
    pass


class Client:

    def __init__(self, model: str = os.environ.get("MODEL_NAME", MODEL_NAME)):
        self.openai = OpenAI(
            api_key=os.environ.get("OPENAI_API_KEY", ""),
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1/"),
        )
        self.default_model = model
        self.call_cnt   = 0
        self.token_cost = 0
        try:
            self.tokenizer = tiktoken.get_encoding("cl100k_base")
        except Exception:
            self.tokenizer = None

    def call_llm(
        self,
        messages:    List[Dict],
        log_msgs:    List[Any],
        model:       str = "",
        max_retries: int = 6,
    ) -> str:
        if not model:
            model = self.default_model

        trimmed = self._trim_messages(messages)

        for attempt in range(max_retries):
            try:
                response = self.openai.chat.completions.create(
                    model=model,
                    messages=trimmed,
                    max_completion_tokens=MAX_TOKENS,
                    temperature=TEMPERATURE,
                )
                reply = response.choices[0].message.content or ""
                self.call_cnt += 1
                if response.usage:
                    self.token_cost += response.usage.total_tokens
                if reply:
                    log_msgs.append({"role": "assistant", "content": reply})
                return reply

            except Exception as e:
                wait = 2 ** attempt  # 指数退避
                print(f"[LLM] 调用失败 (attempt {attempt+1}/{max_retries}): {e}，{wait}s 后重试")
                time.sleep(wait)

        raise APIUnavailableError(f"API 连续失败 {max_retries} 次，服务不可用")

    def _trim_messages(self, messages: List[Dict]) -> List[Dict]:
        """超出 MAX_HISTORY_CHARS 时从头部丢弃旧消息，始终保留 system prompt。"""
        if not messages:
            return messages
        total = sum(len(str(m.get("content", ""))) for m in messages)
        if total <= MAX_HISTORY_CHARS:
            return messages
        system = [m for m in messages if m.get("role") == "system"]
        rest   = [m for m in messages if m.get("role") != "system"]
        while len(rest) > 1 and sum(len(str(m.get("content", ""))) for m in system + rest) > MAX_HISTORY_CHARS:
            rest.pop(0)
        return system + rest

    def print_stats(self):
        print(f"[LLM Stats] 调用次数: {self.call_cnt}  |  Token 消耗: {self.token_cost}")
