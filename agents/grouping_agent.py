from typing import List, Dict
from agents.base_agent import BaseAgent
from data_types import HunkRecord
from prompts import get_intent_record_prompt, get_intent_match_prompt


class GroupingAgent(BaseAgent):

    def generate_intent_record(self, hunk: HunkRecord) -> Dict:
        messages = get_intent_record_prompt(hunk.raw_str, hunk.supplemental_context)
        reply = self.chat(messages)

        parsed = self.parse_json(reply)
        if parsed:
            record = {
                "hunk_index":      hunk.hunk_index,
                "change_category": parsed.get("change_category", "other"),
                "intent_summary":  parsed.get("intent_summary", ""),
                "what":            parsed.get("what", ""),
                "how":             parsed.get("how", ""),
            }
        else:
            record = {
                "hunk_index":      hunk.hunk_index,
                "change_category": "other",
                "intent_summary":  reply.strip(),
                "what":            "",
                "how":             "",
            }

        self.log({"intent_record": record})
        return record

    def greedy_grouping(self, hunks: List[HunkRecord], intent_records: List[Dict]) -> List[Dict]:
        groups: List[Dict] = []

        for hunk, record in zip(hunks, intent_records):
            category = record["change_category"]
            intent   = record["intent_summary"]

            candidates = [g for g in groups if g["change_category"] == category]
            matched_group = None
            for group in candidates:
                if self._intent_match(intent, group["representative_intent"]):
                    matched_group = group
                    break

            if matched_group:
                matched_group["hunks"].append(hunk)
                matched_group["intent_records"].append(record)
                matched_group["representative_intent"] = self._update_representative(
                    matched_group["intent_records"]
                )
            else:
                groups.append({
                    "group_id":              len(groups),
                    "change_category":       category,
                    "representative_intent": intent,
                    "hunks":                 [hunk],
                    "intent_records":        [record],
                    "passed_review":         False,
                    "core_intent":           "",
                })

        self.log({"grouping_result": [
            {
                "group_id":   g["group_id"],
                "category":   g["change_category"],
                "hunk_count": len(g["hunks"]),
                "intent":     g["representative_intent"],
            }
            for g in groups
        ]})
        return groups

    def refine_group(
        self,
        groups:         List[Dict],
        target_group:   Dict,
        abnormal_hunks: List[int],
    ) -> List[Dict]:
        """将 target_group 中的异常 hunk 剔除，重新分配到合适分组。"""
        normal_records     = [r for r in target_group["intent_records"] if r["hunk_index"] not in abnormal_hunks]
        normal_hunks       = [h for h in target_group["hunks"]          if h.hunk_index not in abnormal_hunks]
        abnormal_records   = [r for r in target_group["intent_records"] if r["hunk_index"] in abnormal_hunks]
        abnormal_hunk_objs = [h for h in target_group["hunks"]          if h.hunk_index in abnormal_hunks]

        target_group["hunks"]          = normal_hunks
        target_group["intent_records"] = normal_records
        if normal_records:
            target_group["representative_intent"] = self._update_representative(normal_records)

        for hunk, record in zip(abnormal_hunk_objs, abnormal_records):
            category = record["change_category"]
            intent   = record["intent_summary"]
            candidates = [g for g in groups if g["change_category"] == category and g is not target_group]
            matched = None
            for g in candidates:
                if self._intent_match(intent, g["representative_intent"]):
                    matched = g
                    break

            if matched:
                matched["hunks"].append(hunk)
                matched["intent_records"].append(record)
                matched["representative_intent"] = self._update_representative(matched["intent_records"])
            else:
                groups.append({
                    "group_id":              len(groups),
                    "change_category":       category,
                    "representative_intent": intent,
                    "hunks":                 [hunk],
                    "intent_records":        [record],
                    "passed_review":         False,
                    "core_intent":           "",
                })

        return groups

    def _intent_match(self, intent_a: str, intent_b: str) -> bool:
        """用 LLM 判断两条意图是否语义匹配。"""
        messages = get_intent_match_prompt(intent_a, intent_b)
        reply    = self.chat(messages)
        return "yes" in reply.lower().split()[0] if reply.strip() else False

    def _update_representative(self, intent_records: List[Dict]) -> str:
        if not intent_records:
            return ""
        if len(intent_records) == 1:
            return intent_records[0]["intent_summary"]
        # 多条时取最后加入的摘要（贪心策略，避免额外 LLM 调用）
        return intent_records[-1]["intent_summary"]
