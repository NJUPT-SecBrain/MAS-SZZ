from typing import List, Dict, Optional, Tuple
from agents.base_agent import BaseAgent
from data_types import HunkRecord, VulnStatement
from tools.context_retriever import retrieve_context
from prompts import (
    get_vuln_stmt_initial_prompt,
    get_suspect_context_prompt,
    get_vuln_stmt_final_prompt,
    get_semantic_completeness_prompt,
)


class VulnStatementAgent(BaseAgent):

    def run(
        self,
        root_cause:      str,
        relevant_groups: List[Dict],
        repo_path:       str,
        fix_commit:      str = "",
    ) -> List[VulnStatement]:
        candidates, confidence, sufficient = self._initial_determination(root_cause, relevant_groups)

        hunk_fix_map = {h.hunk_index: h.fix_commit for g in relevant_groups for h in g["hunks"]}
        first_evidence = []
        for c in candidates:
            first_evidence.append({
                "hunk_index": c["hunk_index"],
                "file_path":  c["file_path"],
                "lineno":     c["lineno"],
                "content":    c["content"],
                "intent":     self._get_intent(c["hunk_index"], relevant_groups),
                "rationale":  c["rationale"],
                "fix_commit": hunk_fix_map.get(c["hunk_index"], ""),
            })

        second_evidence = []
        if not sufficient:
            all_hunks = [h for g in relevant_groups for h in g["hunks"]]
            missing_list = self._check_completeness(all_hunks)
            suspect_snippets = self._retrieve_suspect_contexts(
                all_hunks, missing_list, root_cause, repo_path, fix_commit
            )
            second_evidence = self._build_second_evidence(suspect_snippets, root_cause)

        return self._final_determination(root_cause, first_evidence, second_evidence)

    def _initial_determination(
        self,
        root_cause:      str,
        relevant_groups: List[Dict],
    ) -> Tuple[List[Dict], str, bool]:
        """返回 (candidates, confidence, sufficient)"""
        messages = get_vuln_stmt_initial_prompt(root_cause, relevant_groups)
        reply    = self.chat(messages)

        parsed = self.parse_json(reply)
        if parsed:
            raw_candidates = parsed.get("candidates", [])
            confidence     = parsed.get("confidence", "low")
            sufficient     = parsed.get("sufficient", False)
        else:
            raw_candidates = []
            confidence     = "low"
            sufficient     = False

        candidates = []
        for c in raw_candidates:
            stmt_text  = c.get("stmt_text", "").strip()
            hunk_index = c.get("hunk_index", 0)
            file_path  = c.get("file_path", "")

            lineno, actual_file = self._match_stmt_to_lineno(
                stmt_text, hunk_index, file_path, relevant_groups
            )
            if actual_file:  # 用 hunk 里的路径覆盖 LLM 可能写错的路径
                file_path = actual_file

            candidates.append({
                "hunk_index": hunk_index,
                "file_path":  file_path,
                "lineno":     lineno or -1,
                "content":    stmt_text,
                "rationale":  c.get("rationale", ""),
            })

        self.log({"vuln_stmt_initial": {
            "candidates": candidates,
            "confidence": confidence,
            "sufficient": sufficient,
        }})
        return candidates, confidence, sufficient

    def _match_stmt_to_lineno(
        self,
        stmt_text:       str,
        hunk_index:      int,
        file_path:       str,
        relevant_groups: List[Dict],
    ) -> Tuple[Optional[int], Optional[str]]:
        """
        在 hunk 删除行/上下文行中匹配语句文本，返回 (lineno, actual_file_path)。
        先按文件路径精确匹配，失败后放宽路径限制（LLM 可能写错文件名）。
        """
        norm_stmt = "".join(stmt_text.split())

        def _search(hunks, ignore_file=False):
            for hunk in hunks:
                if not ignore_file and hunk.file_path != file_path and file_path:
                    continue
                # 优先删除行
                for lineno, content in hunk.deleted_lines:
                    if stmt_text in content or content.strip() == stmt_text:
                        return lineno, hunk.file_path
                    if norm_stmt and norm_stmt in "".join(content.split()):
                        return lineno, hunk.file_path
                # 上下文行（纯新增 patch 兜底）
                for old_lineno, new_lineno, content in hunk.context_lines:
                    c = content.strip()
                    if not c:
                        continue
                    if stmt_text in c or c == stmt_text:
                        return old_lineno, hunk.file_path
                    norm_c = "".join(c.split())
                    if norm_stmt and (norm_stmt in norm_c or norm_c in norm_stmt):
                        return old_lineno, hunk.file_path
            return None, None

        all_hunks = [h for g in relevant_groups for h in g["hunks"]]
        lineno, actual_file = _search(all_hunks, ignore_file=False)
        if lineno is not None:
            return lineno, actual_file
        return _search(all_hunks, ignore_file=True)

    def _check_completeness(self, hunks: List[HunkRecord]) -> List[str]:
        missing_all = []
        for hunk in hunks:
            messages = get_semantic_completeness_prompt(
                hunk.raw_str, hunk.supplemental_context, task="vuln_stmt"
            )
            reply  = self.chat(messages)
            parsed = self.parse_json(reply)
            if parsed and not parsed.get("complete", True):
                missing_all.extend(parsed.get("missing", []))
        return missing_all

    def _retrieve_suspect_contexts(
        self,
        hunks:      List[HunkRecord],
        missing:    List[str],
        root_cause: str,
        repo_path:  str,
        fix_commit: str = "",
    ) -> List[Dict]:
        snippets = []
        seen     = set()
        for hunk in hunks:
            context = retrieve_context(
                hunk=hunk,
                missing=missing if missing else ["function definition", "variable declaration"],
                repo_path=repo_path,
                commit=hunk.fix_commit or fix_commit,
                context_lines=15,
            )
            if context and context not in seen:
                seen.add(context)
                snippets.append({"symbol": hunk.file_path, "snippet": context})
        return snippets

    def _build_second_evidence(self, suspect_snippets: List[Dict], root_cause: str) -> List[Dict]:
        evidence = []
        for item in suspect_snippets:
            messages = get_suspect_context_prompt(root_cause, item["snippet"], item["symbol"])
            reply    = self.chat(messages)
            parsed   = self.parse_json(reply)

            rationale       = parsed.get("rationale", "") if parsed else reply.strip()
            relevance_score = float(parsed.get("relevance_score", 0.5)) if parsed else 0.5

            if relevance_score >= 0.4:
                evidence.append({
                    "symbol":          item["symbol"],
                    "snippet":         item["snippet"],
                    "rationale":       rationale,
                    "relevance_score": relevance_score,
                })

        self.log({"second_evidence_count": len(evidence)})
        return evidence

    def _final_determination(
        self,
        root_cause:      str,
        first_evidence:  List[Dict],
        second_evidence: List[Dict],
    ) -> List[VulnStatement]:
        messages = get_vuln_stmt_final_prompt(root_cause, first_evidence, second_evidence)
        reply    = self.chat(messages)
        parsed   = self.parse_json(reply)

        if not parsed:
            self.log({"vuln_stmt_final": "parse_failed"})
            return []

        self.log({"vuln_stmt_final": parsed})

        results = []
        for item in parsed.get("vuln_statements", []):
            stmt_text = item.get("stmt_text", "").strip()
            file_path = item.get("vuln_file", "")
            if not stmt_text:
                continue

            # 从 first_evidence 里匹配行号（精确 + 归一化模糊匹配）
            lineno    = -1
            norm_stmt = "".join(stmt_text.split())
            for e in first_evidence:
                e_content = e.get("content", "")
                norm_e    = "".join(e_content.split())
                if (stmt_text in e_content or e_content.strip() == stmt_text
                        or (norm_stmt and norm_stmt in norm_e)
                        or (norm_stmt and norm_e in norm_stmt)):
                    lineno = e.get("lineno", -1)
                    if not file_path:
                        file_path = e.get("file_path", "")
                    break

            results.append(VulnStatement(
                file_path=  file_path,
                lineno=     lineno,
                content=    stmt_text,
                hunk_index= first_evidence[0]["hunk_index"] if first_evidence else -1,
                fix_commit= first_evidence[0].get("fix_commit", "") if first_evidence else "",
                confidence= 1.0 if item.get("location") == "hunk" else 0.8,
            ))
        return results

    def _get_intent(self, hunk_index: int, groups: List[Dict]) -> str:
        for g in groups:
            for r in g["intent_records"]:
                if r["hunk_index"] == hunk_index:
                    return r["intent_summary"]
        return ""
