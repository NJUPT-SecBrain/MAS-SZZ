import json
import re
from typing import Any, Dict, List, Optional
from llm import Client
from constants import MODEL_NAME


class BaseAgent:
    def __init__(self, client: Client, log_msgs: List[Any]) -> None:
        self.client   = client
        self.log_msgs = log_msgs

    def chat(self, messages: List[Dict], model: str = "") -> str:
        self.log_msgs.extend(messages)
        reply = self.client.call_llm(messages, self.log_msgs, model=model)
        return reply

    @staticmethod
    def parse_json(text: str) -> Optional[Dict]:
        """从 LLM 回复中提取 JSON，兼容 ```json fence 和裸 JSON。"""
        clean = re.sub(r"```(?:json)?\s*", "", text).replace("```", "").strip()
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", clean, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass
        return None

    def log(self, data: Any) -> None:
        self.log_msgs.append(data)

    def run(self, *args, **kwargs):
        raise NotImplementedError
