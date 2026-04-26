from agents.base_agent import BaseAgent
from data_types import RootCause
from prompts import get_root_cause_analysis_prompt


class RootCauseAgent(BaseAgent):

    def run(
        self,
        cve_description: str,
        patch_content:   str,
        commit_message:  str,
        feedback:        str = "",
    ) -> RootCause:

        messages = get_root_cause_analysis_prompt(
            cve_description, patch_content, commit_message, feedback
        )
        reply = self.chat(messages)

        text, evidence = "", ""
        for line in reply.split("\n"):
            if line.lower().startswith("root cause:"):
                text = line.split(":", 1)[-1].strip()
            elif line.lower().startswith("evidence:"):
                evidence = line.split(":", 1)[-1].strip()

        if not text:
            text = reply.strip()

        self.log({"root_cause_candidate": text, "evidence_points": evidence})
        return RootCause(text=text, evidence_points=evidence)
