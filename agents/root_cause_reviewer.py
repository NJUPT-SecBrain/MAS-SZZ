from agents.base_agent import BaseAgent
from data_types import RootCause
from prompts import get_root_cause_review_prompt


class RootCauseReviewer(BaseAgent):

    def run(
        self,
        candidate:       RootCause,
        patch_content:   str,
        cve_description: str,
        commit_message:  str,
    ) -> tuple:
        """返回 (passed: bool, feedback: str)"""
        messages = get_root_cause_review_prompt(
            candidate.text,
            candidate.evidence_points,
            patch_content,
            cve_description,
            commit_message,
        )
        reply = self.chat(messages)

        passed   = False
        feedback = ""
        for line in reply.split("\n"):
            lower = line.lower()
            if lower.startswith("verdict:"):
                passed = "pass" in lower
            elif lower.startswith("feedback:"):
                feedback = line.split(":", 1)[-1].strip()

        if not passed and "pass" in reply.lower() and "fail" not in reply.lower():
            passed = True

        self.log({"root_cause_review": {"passed": passed, "feedback": feedback}})
        return passed, feedback
