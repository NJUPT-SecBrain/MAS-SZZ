"""
pipeline.py
─────────────────────────────────────────────
主控制流。
输入：一条 DatasetEntry
输出：PipelineState（含最终 BIC 结果）

流程：
  步骤1：根因分析（RootCauseAgent + RootCauseReviewer）
  步骤2：hunk解析 → 语义补全 → 分组 → 审查 → 相关性筛选
  步骤3：漏洞语句定位（VulnStatementAgent）
  步骤4：BIC回溯定位（BICAgent）
"""

import os
import json
import subprocess
import traceback
from typing import Optional

from data_types import DatasetEntry, PipelineState
from llm import Client
from agents.root_cause_agent import RootCauseAgent
from agents.root_cause_reviewer import RootCauseReviewer
from agents.semantic_completeness_agent import SemanticCompletenessAgent
from agents.grouping_agent import GroupingAgent
from agents.reviewer_agent import ReviewerAgent
from agents.vuln_statement_agent import VulnStatementAgent
from agents.bic_agent import BICAgent
from tools.patch_parser import parse_patch
from tools.context_retriever import retrieve_context
from constants import (
    REPOS_DIR, CVE_DESC_PATH,
    MAX_ROOT_CAUSE_RETRIES, SAVE_LOGS_DIR,
)


class Pipeline:

    def __init__(self, client: Client):
        self.client = client

    def run(self, entry: DatasetEntry) -> PipelineState:
        """
        执行完整 pipeline，返回填充好的 PipelineState。
        任何步骤出错都会被捕获，写入 state.error，继续返回。
        """
        state = PipelineState(entry=entry)

        try:
            self._step1_root_cause(state)
            self._step2_hunk_grouping(state)
            self._step3_vuln_statement(state)
            self._step4_bic_tracing(state)
        except Exception as e:
            state.error = traceback.format_exc()
            print(f"[Pipeline] {entry.cveid} 运行异常: {e}")

        # 记录本条的LLM调用统计
        state.llm_call_count  = self.client.call_cnt
        state.llm_token_count = self.client.token_cost
        return state

    # ══════════════════════════════════════════════════════════
    # 步骤1：根因分析
    # ══════════════════════════════════════════════════════════
    def _step1_root_cause(self, state: PipelineState):
        print(f"  [Step1] 根因分析...")

        # 加载数据
        state.patch_content   = self._get_patch(state)
        state.commit_message  = self._get_commit_msg(state)
        state.cve_description = self._get_cve_desc(state)

        agent    = RootCauseAgent(self.client, state.log_msgs)
        reviewer = RootCauseReviewer(self.client, state.log_msgs)

        feedback = ""
        for i in range(MAX_ROOT_CAUSE_RETRIES):
            root_cause = agent.run(
                cve_description=state.cve_description,
                patch_content=state.patch_content,
                commit_message=state.commit_message,
                feedback=feedback,
            )
            passed, feedback = reviewer.run(
                candidate=root_cause,
                patch_content=state.patch_content,
                cve_description=state.cve_description,
                commit_message=state.commit_message,
            )
            root_cause.passed_review = passed
            root_cause.feedback      = feedback

            if passed:
                print(f"    根因（第{i+1}轮通过）: {root_cause.text[:80]}")
                break

        state.root_cause = root_cause

    # ══════════════════════════════════════════════════════════
    # 步骤2：hunk分组与筛选
    # ══════════════════════════════════════════════════════════
    def _step2_hunk_grouping(self, state: PipelineState):
        print(f"  [Step2] hunk分组筛选...")

        repo_path = self._repo_path(state)

        # 解析所有 fix commit 的 patch，合并 hunks
        all_hunks = []
        for fix_commit in state.fix_commit_hashes:
            try:
                patch = subprocess.check_output(
                    f"git show -m {fix_commit}",
                    shell=True, cwd=repo_path,
                    stderr=subprocess.DEVNULL,
                ).decode("utf-8", errors="ignore")
            except Exception:
                continue
            for h in parse_patch(patch):
                h.fix_commit = fix_commit
                all_hunks.append(h)

        hunks = all_hunks
        if not hunks:
            print(f"    无hunk，跳过")
            return

        sc_agent  = SemanticCompletenessAgent(self.client, state.log_msgs)
        grouper   = GroupingAgent(self.client, state.log_msgs)
        reviewer  = ReviewerAgent(self.client, state.log_msgs)

        # 2.1 语义完备性判定 + 上下文补全
        for hunk in hunks:
            is_complete, missing = sc_agent.run(hunk, task="grouping")
            if not is_complete and missing:
                context = retrieve_context(
                    hunk=hunk, missing=missing,
                    repo_path=repo_path, commit=hunk.fix_commit,
                )
                hunk.supplemental_context = context

        # 2.2 + 2.3 生成意图记录 + 贪心分组
        intent_records = [grouper.generate_intent_record(h) for h in hunks]
        groups = grouper.greedy_grouping(hunks, intent_records)

        # 2.4 / 2.5 一致性审查循环
        MAX_ITER = 3
        for _ in range(MAX_ITER):
            all_passed = True
            for group in list(groups):
                verdict, core_intent, outliers, reason = reviewer.review_consistency(group)
                group["passed_review"] = (verdict == "ACCEPT")
                if verdict == "REJECT":
                    all_passed = False
                    groups = grouper.refine_group(groups, group, outliers)
            if all_passed:
                break

        # 2.6 漏洞相关性筛选
        root_cause_text = state.root_cause.text if state.root_cause else ""
        relevant_groups = []
        for group in groups:
            is_relevant, _ = reviewer.review_relevance(group, root_cause_text)
            if is_relevant:
                relevant_groups.append(group)

        # 兜底：全部被过滤时用所有分组，让步骤3的LLM自行判断
        if not relevant_groups:
            relevant_groups = groups
            state.used_fallback = True
            print(f"    相关性筛选全部过滤，兜底使用全部 {len(groups)} 个分组")

        # 把相关 hunk 存入 state
        state.hunks = [h for g in relevant_groups for h in g["hunks"]]
        print(f"    相关hunk数: {len(state.hunks)} / {len(hunks)}")
        state._relevant_groups = relevant_groups

    # ══════════════════════════════════════════════════════════
    # 步骤3：漏洞语句定位
    # ══════════════════════════════════════════════════════════
    def _step3_vuln_statement(self, state: PipelineState):
        print(f"  [Step3] 漏洞语句定位...")

        relevant_groups = getattr(state, "_relevant_groups", [])
        if not relevant_groups:
            print(f"    无相关分组，跳过")
            return

        agent = VulnStatementAgent(self.client, state.log_msgs)
        vuln_stmts = agent.run(
            root_cause=state.root_cause.text,
            relevant_groups=relevant_groups,
            repo_path=self._repo_path(state),
        )

        if vuln_stmts:
            state.vuln_statements = vuln_stmts
            for v in vuln_stmts:
                lineno_str = str(v.lineno) if v.lineno > 0 else "?"
                print(f"    漏洞语句: {v.file_path}:{lineno_str} → {v.content[:60]}")
        else:
            print(f"    未能定位漏洞语句")

    # ══════════════════════════════════════════════════════════
    # 步骤4：BIC回溯定位
    # ══════════════════════════════════════════════════════════
    def _step4_bic_tracing(self, state: PipelineState):
        print(f"  [Step4] BIC回溯定位...")

        agent = BICAgent(self.client, state.log_msgs)

        # ── 步骤3有漏洞语句：正常回溯 ────────────────────────
        if state.vuln_statements:
            bic_list, trace_log = agent.run(
                vuln_stmts= state.vuln_statements,
                root_cause= state.root_cause.text,
                repo_path=  self._repo_path(state),
                fix_commit= state.fix_commit_hash,
            )
            if bic_list:
                state.final_bic = bic_list
                print(f"    预测BIC: {[b[:12] for b in bic_list]}")
                return
            print(f"    blame回溯未找到BIC，尝试兜底...")

        # ── 兜底：对所有相关hunk删除行分别blame，投票 ─────────
        relevant_groups = getattr(state, "_relevant_groups", [])
        if not relevant_groups:
            print(f"    无相关分组，跳过")
            return

        # 收集锚点行：优先删除行，纯新增时用上下文行
        all_deleted = []
        for g in relevant_groups:
            for hunk in g["hunks"]:
                for lineno, content in hunk.deleted_lines:
                    if lineno > 0 and content.strip():
                        all_deleted.append((hunk.file_path, lineno, content, hunk.fix_commit))
                if not hunk.deleted_lines:
                    for old_lineno, new_lineno, content in hunk.context_lines:
                        if old_lineno > 0 and content.strip():
                            all_deleted.append((hunk.file_path, old_lineno, content, hunk.fix_commit))

        if not all_deleted:
            print(f"    无可用锚点行，跳过")
            return

        # 从根因提取关键符号
        import re as _re
        C_KEYWORDS = {
            "if", "else", "for", "while", "do", "switch", "case", "return",
            "break", "continue", "goto", "sizeof", "typeof", "static",
            "const", "void", "int", "long", "char", "unsigned", "struct",
            "enum", "typedef", "extern", "NULL", "true", "false",
        }
        root_cause_text = state.root_cause.text if state.root_cause else ""
        rc_symbols = [
            s for s in _re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]{3,})\b", root_cause_text)
            if s not in C_KEYWORDS
        ]

        # 对每个删除行打分：匹配到的根因关键词数量
        def score_line(content: str) -> int:
            return sum(1 for sym in rc_symbols if sym in content)

        # 按得分排序，取得分最高的前3行
        scored = sorted(all_deleted, key=lambda x: score_line(x[2]), reverse=True)
        anchors = scored[:3]

        print(f"    [兜底] 选出 {len(anchors)} 个锚点（共{len(all_deleted)}个锚点行）...")
        for f, l, c, _ in anchors:
            print(f"      得分{score_line(c)} {f}:{l} → {c.strip()[:60]}")

        from tools.vcs_tools import git_blame_line, get_parent_commit
        repo_path = self._repo_path(state)

        vote: dict = {}
        for file_path, lineno, content, hunk_fix_commit in anchors:
            parent = get_parent_commit(repo_path, hunk_fix_commit or state.fix_commit_hash)
            if not parent:
                continue
            blame, _ = git_blame_line(repo_path, parent, file_path, lineno)
            if blame:
                vote[blame] = vote.get(blame, 0) + 1

        if vote:
            best = max(vote, key=lambda h: vote[h])
            state.final_bic = [best]
            state.used_fallback = True
            state.log_msgs.append({
                "bic_method":  "deleted_line_vote",
                "anchors":     [(f, l, c.strip()[:60]) for f, l, c, _ in anchors],
                "vote":        {k[:12]: v for k, v in vote.items()},
                "winner":      best[:12],
            })
            print(f"    [兜底] 预测BIC: {best[:12]} (得票{vote[best]}/{len(anchors)})")
        else:
            print(f"    兜底也未能定位BIC")

    # ══════════════════════════════════════════════════════════
    # 工具方法
    # ══════════════════════════════════════════════════════════
    def _repo_path(self, state: PipelineState) -> str:
        return os.path.join(REPOS_DIR, state.repo_name)

    def _get_patch(self, state: PipelineState) -> str:
        parts = []
        for commit in state.fix_commit_hashes:
            try:
                out = subprocess.check_output(
                    f"git show -m {commit}",
                    shell=True, cwd=self._repo_path(state),
                    stderr=subprocess.DEVNULL,
                ).decode("utf-8", errors="ignore")
                parts.append(out)
            except Exception:
                pass
        return "\n".join(parts)

    def _get_commit_msg(self, state: PipelineState) -> str:
        parts = []
        for commit in state.fix_commit_hashes:
            try:
                out = subprocess.check_output(
                    f"git log -1 --pretty=%B {commit}",
                    shell=True, cwd=self._repo_path(state),
                    stderr=subprocess.DEVNULL,
                ).decode("utf-8", errors="ignore").strip()
                if out:
                    parts.append(out)
            except Exception:
                pass
        return "\n---\n".join(parts)

    def _get_cve_desc(self, state: PipelineState) -> str:
        try:
            with open(CVE_DESC_PATH, encoding="utf-8") as f:
                descs = json.load(f)
            return descs.get(state.cveid, "No description available.")
        except Exception:
            return ""


def save_state(state: PipelineState, base_dir: str = ""):
    """将 PipelineState 保存为 JSON 日志文件。"""
    root = base_dir or SAVE_LOGS_DIR
    log_dir = os.path.join(root, state.repo_name, state.fix_commit_hashes[0])
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, "result.json")

    # 从 log_msgs 里提取各智能体的结构化日志
    agent_logs = [
        msg for msg in state.log_msgs
        if isinstance(msg, dict) and "role" not in msg
    ]

    # 判断BIC来源方法
    bic_method = "unknown"
    for log in agent_logs:
        if isinstance(log, dict):
            if log.get("bic_found"):
                bic_method = "blame_trace"
                break
            elif log.get("bic_method") == "deleted_line_vote":
                bic_method = "deleted_line_vote"
                break

    result = {
        "cveid":            state.cveid,
        "repo_name":        state.repo_name,
        "fix_commit_hashes": state.fix_commit_hashes,
        "ground_truth_bic": state.ground_truth_bic,
        "predicted_bic":    state.final_bic,
        "correct":          state.ground_truth_bic in state.final_bic,
        "bic_method":       bic_method,
        "llm_calls":        state.llm_call_count,
        "llm_tokens":       state.llm_token_count,

        # 步骤1
        "root_cause": {
            "text":           state.root_cause.text if state.root_cause else "",
            "evidence":       state.root_cause.evidence_points if state.root_cause else "",
            "passed_review":  state.root_cause.passed_review if state.root_cause else None,
        },

        # 步骤3
        "vuln_statements": [
            {
                "file":       v.file_path,
                "lineno":     v.lineno,
                "content":    v.content,
                "confidence": v.confidence,
            }
            for v in state.vuln_statements
        ],

        # 智能体判断过程（结构化日志）
        "agent_logs": agent_logs,

        # 运行状态
        "used_fallback": state.used_fallback,
        "error":         state.error,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return path
