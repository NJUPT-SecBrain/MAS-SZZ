from typing import Optional, List, Dict, Tuple
from agents.base_agent import BaseAgent
from data_types import VulnStatement
from tools.vcs_tools import (
    git_blame_line,
    get_parent_commit,
    get_commit_message,
    get_file_diff_at_commit,
    get_function_at_commit,
)
from prompts import get_bic_determination_prompt


class BICAgent(BaseAgent):

    MAX_TRACE_DEPTH = 20  # 防止在循环引用的 commit 图里死循环

    def run(
        self,
        vuln_stmts: List[VulnStatement],
        root_cause: str,
        repo_path:  str,
        fix_commit: str,
    ) -> Tuple[List[str], List[Dict]]:
        """对多个漏洞语句分别回溯，投票合并，返回 (bic_list, trace_log)。"""
        all_traces = []
        bic_votes  = {}

        for vuln_stmt in vuln_stmts:
            print(f"  回溯漏洞语句: {vuln_stmt.file_path}:{vuln_stmt.lineno}")
            bic_hash, trace_log = self._trace_single(vuln_stmt, root_cause, repo_path, fix_commit)
            all_traces.extend(trace_log)
            if bic_hash:
                bic_votes[bic_hash] = bic_votes.get(bic_hash, 0) + 1

        if not bic_votes:
            return [], all_traces

        sorted_bics = sorted(bic_votes, key=lambda h: bic_votes[h], reverse=True)
        self.log({"bic_votes": bic_votes, "bic_candidates": sorted_bics})
        return sorted_bics, all_traces

    def _trace_single(
        self,
        vuln_stmt:  VulnStatement,
        root_cause: str,
        repo_path:  str,
        fix_commit: str,
    ) -> Tuple[Optional[str], List[Dict]]:
        anchor_file   = vuln_stmt.file_path
        anchor_lineno = vuln_stmt.lineno
        anchor_commit = get_parent_commit(repo_path, vuln_stmt.fix_commit or fix_commit)

        if not anchor_commit:
            self.log({"bic_error": "cannot get parent of fix_commit"})
            return None, []

        trace_log   = []
        prev_commit = None  # 上一个判定为"存在漏洞"的 commit

        for depth in range(self.MAX_TRACE_DEPTH):
            blame_commit, orig_lineno = git_blame_line(
                repo_path, anchor_commit, anchor_file, anchor_lineno
            )

            if not blame_commit:
                self.log({"bic_trace": f"blame failed at depth {depth}"})
                break

            if orig_lineno is None:
                orig_lineno = anchor_lineno

            blame_parent = get_parent_commit(repo_path, blame_commit)
            commit_msg   = get_commit_message(repo_path, blame_commit)
            diff         = get_file_diff_at_commit(repo_path, blame_commit, anchor_file)

            exists, sufficient, reason = self._determine_vuln_exists(
                root_cause, blame_commit, anchor_file, orig_lineno, diff, "diff", commit_msg
            )

            # diff 上下文不足时，改用完整函数体判定
            if not sufficient:
                func_body = get_function_at_commit(repo_path, blame_commit, anchor_file, orig_lineno)
                if func_body.strip():
                    exists, _, reason = self._determine_vuln_exists(
                        root_cause, blame_commit, anchor_file, orig_lineno,
                        func_body, "function", commit_msg
                    )
                else:
                    exists = False
                    reason = "code snippet is empty, file/function not present"

            record = {
                "depth":          depth,
                "blame_input":    {"anchor_commit": anchor_commit[:12],
                                   "anchor_file": anchor_file,
                                   "anchor_lineno": anchor_lineno},
                "commit":         blame_commit,
                "commit_short":   blame_commit[:12],
                "commit_msg":     commit_msg[:120],
                "loc_method":     "blame_orig_lineno",
                "display_file":   anchor_file,
                "display_lineno": orig_lineno,
                "code_snippet":   diff[:500] if diff else "",
                "exists":         exists,
                "reason":         reason,
            }
            trace_log.append(record)
            self.log({"bic_trace_step": record})

            print(f"  [depth {depth}] {blame_commit[:12]} "
                  f"{'存在漏洞' if exists else '不存在漏洞'} - {reason[:60]}")

            if not exists:
                if prev_commit:
                    self.log({"bic_found": prev_commit, "depth": depth})
                    return prev_commit, trace_log
                else:
                    self.log({"bic_found": blame_commit, "note": "first step no-vuln"})
                    return blame_commit, trace_log

            prev_commit   = blame_commit
            if not blame_parent:
                self.log({"bic_found": blame_commit, "note": "reached root commit"})
                return blame_commit, trace_log

            anchor_commit = blame_parent
            anchor_lineno = orig_lineno

        # 超出最大深度
        result = prev_commit or blame_commit if trace_log else None
        self.log({"bic_found": result, "note": "max depth reached"})
        return result, trace_log

    def _determine_vuln_exists(
        self,
        root_cause:     str,
        commit_hash:    str,
        file_path:      str,
        lineno:         int,
        code_snippet:   str,
        context_type:   str,
        commit_message: str,
    ) -> Tuple[bool, bool, str]:
        """
        返回 (exists, sufficient, reason)。
        exists=True 当且仅当 has_bug=True AND is_fixed=False；
        sufficient=False 表示上下文不足，需要更大范围的代码。
        """
        messages = get_bic_determination_prompt(
            root_cause, commit_hash, file_path, lineno,
            code_snippet, context_type, commit_message
        )
        reply  = self.chat(messages)
        parsed = self.parse_json(reply)

        if parsed:
            sufficient = bool(parsed.get("sufficient", True))
            has_bug    = bool(parsed.get("has_bug", True))
            is_fixed   = bool(parsed.get("is_fixed", False))
            reason     = parsed.get("reason", "")
            exists     = has_bug and not is_fixed
        else:
            sufficient = True
            exists     = "not exist" not in reply.lower()
            reason     = reply.strip()[:200]

        return exists, sufficient, reason
