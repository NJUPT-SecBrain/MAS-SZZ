from typing import List, Tuple, Dict
from agents.base_agent import BaseAgent
from prompts import get_consistency_review_prompt, get_relevance_review_prompt


class ReviewerAgent(BaseAgent):

    def review_consistency(self, group: Dict) -> Tuple[str, str, List[int], str]:
        """返回 (verdict, core_intent, outlier_hunk_indices, reason)"""
        if len(group["intent_records"]) <= 1:
            core_intent = group["representative_intent"]
            group["core_intent"] = core_intent
            self.log({"consistency_review": {
                "group_id": group["group_id"],
                "verdict":  "ACCEPT",
                "reason":   "single hunk group, auto-accepted",
            }})
            return "ACCEPT", core_intent, [], "single hunk group"

        messages = get_consistency_review_prompt(group)
        reply    = self.chat(messages)

        parsed = self.parse_json(reply)
        if parsed:
            verdict     = parsed.get("verdict", "ACCEPT").upper()
            core_intent = parsed.get("core_intent", group["representative_intent"])
            outliers    = parsed.get("outlier_hunk_indices", [])
            reason      = parsed.get("reason", "")
        else:
            verdict     = "ACCEPT" if "accept" in reply.lower() else "REJECT"
            core_intent = group["representative_intent"]
            outliers    = []
            reason      = reply.strip()

        group["core_intent"] = core_intent
        self.log({"consistency_review": {
            "group_id":    group["group_id"],
            "verdict":     verdict,
            "core_intent": core_intent,
            "outliers":    outliers,
            "reason":      reason,
        }})
        return verdict, core_intent, outliers, reason

    def review_relevance(self, group: Dict, root_cause: str) -> Tuple[bool, str]:
        """返回 (is_relevant, reason)"""
        messages = get_relevance_review_prompt(group, root_cause)
        reply    = self.chat(messages)

        parsed = self.parse_json(reply)
        if parsed:
            is_relevant = parsed.get("verdict", "").upper() == "RELEVANT"
            reason      = parsed.get("reason", "")
        else:
            is_relevant = "relevant" in reply.lower() and "irrelevant" not in reply.lower()
            reason      = reply.strip()

        self.log({"relevance_review": {
            "group_id":    group["group_id"],
            "is_relevant": is_relevant,
            "reason":      reason,
        }})
        return is_relevant, reason
