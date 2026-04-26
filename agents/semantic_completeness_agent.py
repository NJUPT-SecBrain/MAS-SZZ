from typing import Tuple, List
from agents.base_agent import BaseAgent
from data_types import HunkRecord
from prompts import get_semantic_completeness_prompt


class SemanticCompletenessAgent(BaseAgent):

    def run(self, hunk: HunkRecord, task: str = "grouping") -> Tuple[bool, List[str]]:
        """返回 (is_complete, missing_list)"""
        messages = get_semantic_completeness_prompt(hunk.raw_str, hunk.supplemental_context, task)
        reply = self.chat(messages)

        parsed = self.parse_json(reply)
        if parsed:
            is_complete = bool(parsed.get("complete", True))
            missing     = parsed.get("missing", [])
            if isinstance(missing, str):
                missing = [missing]
        else:
            is_complete = "incomplete" not in reply.lower()
            missing = []
            for line in reply.split("\n"):
                line = line.strip()
                if line.startswith("-") or line.startswith("*"):
                    missing.append(line.lstrip("-* ").strip())

        self.log({"semantic_completeness": {
            "hunk_index": hunk.hunk_index,
            "file_path":  hunk.file_path,
            "complete":   is_complete,
            "missing":    missing,
        }})
        return is_complete, missing
