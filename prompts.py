"""
prompts.py
─────────────────────────────────────────────
所有 agent 使用的 prompt 模板。
每个 agent 对应：
  - 一个静态 system prompt（字符串常量）
  - 一个动态 user prompt 生成函数（注入变量）
"""


# ══════════════════════════════════════════════════════════════
# 1. RootCauseAgent
#    输入：CVE描述 + patch内容 + commit message
#    输出：根因文本 + 支撑证据
# ══════════════════════════════════════════════════════════════

ROOT_CAUSE_SYSTEM = """\
You are a Linux kernel security expert specializing in vulnerability root cause analysis.

Your task is to analyze a CVE and its corresponding bug-fixing patch, then identify the \
precise root cause of the vulnerability.

Always respond in the following exact format:
Root cause: <one concise sentence describing the root cause>
Evidence: <key evidence from the patch or CVE description that supports your conclusion>

Rules:
- The root cause must describe WHY the bug exists, not just WHAT the patch does.
- Be specific: mention the subsystem, data structure, or function involved.
- Evidence must be grounded in the actual patch diff or CVE description provided.
- Do not speculate beyond what is shown in the provided information.
"""


def get_root_cause_analysis_prompt(
    cve_description: str,
    patch_content:   str,
    commit_message:  str,
    feedback:        str = "",
) -> list:
    """
    构造 RootCauseAgent 的 messages 列表。
    feedback: 上一轮 Reviewer 的反馈（首次为空）。
    """
    feedback_block = ""
    if feedback:
        feedback_block = f"""
Previous attempt was rejected. Reviewer feedback:
{feedback}

Please revise your analysis accordingly.
"""

    user_content = f"""\
## CVE Description
{cve_description}

## Commit Message
{commit_message}

## Patch Diff
{patch_content}
{feedback_block}
Now analyze the root cause of this vulnerability.
"""

    return [
        {"role": "system",  "content": ROOT_CAUSE_SYSTEM},
        {"role": "user",    "content": user_content},
    ]


# ══════════════════════════════════════════════════════════════
# 2. RootCauseReviewer
#    输入：根因候选 + 支撑证据 + 原始信息
#    输出：审查结论（pass/fail）+ 反馈意见
# ══════════════════════════════════════════════════════════════

ROOT_CAUSE_REVIEW_SYSTEM = """\
You are a strict code reviewer auditing vulnerability root cause analyses.

You will be given:
1. A proposed root cause and its supporting evidence
2. The original CVE description, commit message, and patch diff

Your job is to verify two things:
  A) Evidence sufficiency  - Is the evidence actually present in the patch/CVE?
  B) Consistency           - Does the root cause align with the CVE and commit message?

Always respond in the following exact format:
Verdict: PASS   (or)   Verdict: FAIL
Feedback: <if FAIL, explain specifically what is wrong or missing; if PASS, write "OK">

Rules:
- Be strict. If the root cause is vague or the evidence is fabricated, mark FAIL.
- A root cause that only restates the patch action (e.g. "missing bounds check was added") \
without explaining WHY is insufficient — mark FAIL.
- If both checks pass, mark PASS.
"""


def get_root_cause_review_prompt(
    root_cause_text:   str,
    evidence_points:   str,
    patch_content:     str,
    cve_description:   str,
    commit_message:    str,
) -> list:
    """
    构造 RootCauseReviewer 的 messages 列表。
    """
    user_content = f"""\
## Proposed Root Cause
{root_cause_text}

## Supporting Evidence
{evidence_points}

## Original CVE Description
{cve_description}

## Commit Message
{commit_message}

## Patch Diff
{patch_content}

Please review the proposed root cause.
"""

    return [
        {"role": "system",  "content": ROOT_CAUSE_REVIEW_SYSTEM},
        {"role": "user",    "content": user_content},
    ]


# ══════════════════════════════════════════════════════════════
# 3. SemanticCompletenessAgent
#    输入：hunk 文本 + 上下文
#    输出：是否完整 + 缺失信息列表
# ══════════════════════════════════════════════════════════════

SEMANTIC_COMPLETENESS_SYSTEM = """\
You are a code analysis expert reviewing Linux kernel patches.

Given a diff hunk and optional surrounding context, determine whether the hunk contains \
enough semantic information to understand WHAT the change does and WHICH code element is involved.

Your judgment must be PRACTICAL, not exhaustive:
- If you can identify the changed function/variable/condition name → sufficient
- If you can tell whether it is a bug fix, refactor, or guard addition → sufficient
- Do NOT require full business logic explanation or complete call chain
- Do NOT mark incomplete just because broader system context is missing

Only mark incomplete when a key symbol (function, macro, type) is completely unknown
and cannot be inferred from the hunk itself.

Respond only in JSON format:
{
  "complete": true or false,
  "missing": ["only list symbol names that are truly unresolvable, e.g. 'function wait_barrier definition'"]
}

If complete, return: {"complete": true, "missing": []}
"""


def get_semantic_completeness_prompt(
    hunk_str:   str,
    context:    str = "",
    task:       str = "grouping",   # "grouping" | "vuln_stmt"
) -> list:
    task_desc = {
        "grouping":  "determine if this hunk can be independently understood for grouping purposes",
        "vuln_stmt": "determine if this hunk contains enough context to identify the vulnerable statement",
    }.get(task, "analyze this hunk")

    context_block = f"\n## Supplemental Context (retrieved from repository)\n{context}" if context else ""

    user_content = f"""\
## Diff Hunk
{hunk_str}
{context_block}
Task: {task_desc}

Note: If supplemental context is provided above, use it to resolve unknown symbols \
before deciding completeness.
"""
    return [
        {"role": "system", "content": SEMANTIC_COMPLETENESS_SYSTEM},
        {"role": "user",   "content": user_content},
    ]


# ══════════════════════════════════════════════════════════════
# 4. GroupingAgent - 生成结构化意图记录（2.2）
# ══════════════════════════════════════════════════════════════

INTENT_RECORD_SYSTEM = """\
You are a senior software engineer with deep expertise in Linux kernel development.
Your task is to analyze a diff hunk and produce a structured Intent Profile.

Follow this Intent-Oriented Chain-of-Thought (IO-CoT) reasoning process:

Step 1 - WHAT (Literal Code Change):
  Describe exactly what was changed at the syntactic level.
  Be objective and stick strictly to what the diff shows.

Step 2 - HOW (Functional Impact):
  Explain how this change affects program behavior at runtime.
  What does it enable, prevent, or fix in terms of execution?

Step 3 - WHY (Change Category):
  Infer the developer's high-level intent. Choose ONE category:
    - bug_fix    : corrects incorrect or missing behavior
    - guard      : adds boundary, null, or error check
    - refactor   : restructures without behavior change
    - style      : formatting, naming, or comment only
    - other      : anything that does not fit above

Step 4 - SUMMARY:
  Synthesize steps 1-3 into one concise sentence suitable for a commit message.

Output strictly in JSON format (no markdown, no extra text):
{
  "what": "...",
  "how": "...",
  "change_category": "bug_fix | guard | refactor | style | other",
  "intent_summary": "one concise sentence"
}
"""


def get_intent_record_prompt(hunk_str: str, context: str = "") -> list:
    context_block = f"\n## Supplemental Context\n{context}" if context else ""
    user_content  = f"""\
## Diff Hunk
{hunk_str}
{context_block}
Apply the IO-CoT reasoning process and produce the Intent Profile.
"""
    return [
        {"role": "system", "content": INTENT_RECORD_SYSTEM},
        {"role": "user",   "content": user_content},
    ]


# ══════════════════════════════════════════════════════════════
# 5. GroupingAgent - 意图语义匹配（2.3）
# ══════════════════════════════════════════════════════════════

INTENT_MATCH_SYSTEM = """\
You are comparing two code change intent summaries to decide if they share the same purpose.

Answer with a single word: Yes or No.
- Yes: both intents describe changes driven by the same root purpose
- No : the intents address different problems or different code areas
"""


def get_intent_match_prompt(intent_a: str, intent_b: str) -> list:
    user_content = f"Intent A: {intent_a}\nIntent B: {intent_b}\n\nDo they share the same purpose?"
    return [
        {"role": "system", "content": INTENT_MATCH_SYSTEM},
        {"role": "user",   "content": user_content},
    ]


# ══════════════════════════════════════════════════════════════
# 6. ReviewerAgent - 一致性审查（2.4）
# ══════════════════════════════════════════════════════════════

CONSISTENCY_REVIEW_SYSTEM = """\
You are a senior code reviewer auditing a proposed grouping of diff hunks.

Your task:
1. Identify the LARGEST COHERENT SUBSET: the maximum set of hunks that can be \
explained by a single shared development purpose. Derive a "core intent" from this subset.
2. Detect OUTLIERS: hunks whose individual purpose is logically inconsistent \
with the core intent and cannot be included in the largest coherent subset.

Respond only in JSON format:
{
  "verdict": "ACCEPT" or "REJECT",
  "core_intent": "one sentence describing the shared purpose of the coherent subset",
  "outlier_hunk_indices": [],
  "reason": "brief explanation of why outliers do not fit"
}

If no outliers exist, return verdict ACCEPT with empty outlier list and reason "OK".
"""


def get_consistency_review_prompt(group: dict) -> list:
    records = group["intent_records"]
    hunks_text = "\n".join(
        f"  Hunk {r['hunk_index']}: [{r['change_category']}] {r['intent_summary']}"
        for r in records
    )
    user_content = f"""\
## Group {group['group_id']} (category: {group['change_category']})
Representative intent: {group['representative_intent']}

## Hunk Intent Records
{hunks_text}

Review this group for coherence.
"""
    return [
        {"role": "system", "content": CONSISTENCY_REVIEW_SYSTEM},
        {"role": "user",   "content": user_content},
    ]


# ══════════════════════════════════════════════════════════════
# 7. ReviewerAgent - 漏洞相关性审查（2.6）
# ══════════════════════════════════════════════════════════════

RELEVANCE_REVIEW_SYSTEM = """\
You are a vulnerability analysis expert reviewing whether a group of code changes \
is related to a specific vulnerability root cause.

Compare the group's core intent with the key elements of the root cause.
A group is RELEVANT if its changes directly address or are caused by the vulnerability.
A group is IRRELEVANT if it only does refactoring, style changes, or unrelated fixes.

Respond only in JSON format:
{
  "verdict": "RELEVANT" or "IRRELEVANT",
  "reason": "brief explanation"
}
"""


def get_relevance_review_prompt(group: dict, root_cause: str) -> list:
    user_content = f"""\
## Vulnerability Root Cause
{root_cause}

## Group {group['group_id']} Core Intent
{group.get('core_intent') or group['representative_intent']}

## Hunk Summaries
{chr(10).join(f"  Hunk {r['hunk_index']}: {r['intent_summary']}" for r in group['intent_records'])}

Is this group relevant to the vulnerability root cause?
"""
    return [
        {"role": "system", "content": RELEVANCE_REVIEW_SYSTEM},
        {"role": "user",   "content": user_content},
    ]


# ══════════════════════════════════════════════════════════════
# 8. VulnStatementAgent - 3.1 hunk范围内初次判定
# ══════════════════════════════════════════════════════════════

VULN_STMT_INITIAL_SYSTEM = """\
You are a vulnerability analysis expert specializing in Linux kernel security.

Given a vulnerability root cause and a set of relevant diff hunks with their intent records,
identify the vulnerable statement(s) that embody the root cause.

Use the root cause to determine which line(s) are most directly responsible for the vulnerability.
You may select from any line that existed BEFORE the fix — do NOT select newly added lines.
Return up to 5 candidates to maximize the chance of finding the correct BIC.

stmt_text must be a SINGLE LINE of code, not a multi-line block.

Respond only in JSON format:
{
  "candidates": [
    {
      "hunk_index": <int>,
      "file_path": "<str>",
      "stmt_text": "<EXACT statement text copied from the pre-fix code lines>",
      "source": "deleted | context",
      "rationale": "<why this statement causes the vulnerability>"
    }
  ],
  "confidence": "high | medium | low",
  "sufficient": true or false
}

Set sufficient=true only when candidates are clearly identifiable from the hunks alone.
If no candidates found, return empty list and sufficient=false.
"""


def get_vuln_stmt_initial_prompt(
    root_cause:   str,
    groups:       list,
) -> list:
    """3.1 基于hunk范围内的初次漏洞语句判定。"""
    hunks_text = ""
    for g in groups:
        hunks_text += f"\n### Group {g['group_id']} (core intent: {g.get('core_intent') or g['representative_intent']})\n"
        for r in g["intent_records"]:
            hunk = g["hunks"][g["intent_records"].index(r)]
            pre_fix_lines = []
            for lineno, content in hunk.deleted_lines:
                pre_fix_lines.append((lineno, content))
            for old_lineno, new_lineno, content in hunk.context_lines:
                if content.strip():
                    pre_fix_lines.append((old_lineno, content.strip()))
            pre_fix_lines.sort(key=lambda x: x[0])
            lines_text = "\n".join(f"  {lineno}: {content}" for lineno, content in pre_fix_lines)
            hunks_text += f"""
Hunk {r['hunk_index']} [{r['change_category']}] {hunk.file_path}
Intent: {r['intent_summary']}
Pre-fix code lines:
{lines_text if lines_text else '  (none)'}
"""

    user_content = f"""\
## Vulnerability Root Cause
{root_cause}

## Relevant Hunk Groups
{hunks_text}

Identify the vulnerable statement(s) based on the root cause.
- Select only lines that existed before the fix (do NOT pick newly added lines)
- Copy the statement EXACTLY as shown, no paraphrasing, single line only
"""
    return [
        {"role": "system", "content": VULN_STMT_INITIAL_SYSTEM},
        {"role": "user",   "content": user_content},
    ]


# ══════════════════════════════════════════════════════════════
# 9. VulnStatementAgent - 3.3 嫌疑上下文选中理由生成
# ══════════════════════════════════════════════════════════════

SUSPECT_CONTEXT_SYSTEM = """\
You are a Linux kernel security expert.

Given the vulnerability root cause and a code snippet extracted from the repository,
generate a concise rationale explaining why this code snippet is relevant to the vulnerability.

Respond only in JSON format:
{
  "rationale": "one or two sentences explaining the relevance",
  "relevance_score": 0.0 to 1.0
}
"""


def get_suspect_context_prompt(root_cause: str, context_snippet: str, symbol: str) -> list:
    user_content = f"""\
## Vulnerability Root Cause
{root_cause}

## Code Snippet (symbol: {symbol})
{context_snippet}

Why is this snippet relevant to the vulnerability?
"""
    return [
        {"role": "system", "content": SUSPECT_CONTEXT_SYSTEM},
        {"role": "user",   "content": user_content},
    ]


# ══════════════════════════════════════════════════════════════
# 10. VulnStatementAgent - 3.5 综合判定
# ══════════════════════════════════════════════════════════════

VULN_STMT_FINAL_SYSTEM = """\
You are a senior Linux kernel vulnerability analyst performing final determination
of the vulnerable statement(s) that introduced a security vulnerability.

You are given:
1. The vulnerability root cause
2. First evidence set: (hunk, fix intent, initial rationale) triples
3. Second evidence set: (suspect context snippet, selection rationale) pairs

Your task: determine ALL vulnerable statements as exact code text.

CRITICAL RULES:
- stmt_text MUST be copied EXACTLY from the pre-fix code lines shown in the First Evidence Set
- Do NOT paraphrase, simplify, rename variables, or rewrite in any way
- Copy the COMPLETE line including all arguments, variable names, and punctuation
- Can be multiple statements (at most 5) if the bug spans multiple locations
- Order by confidence (highest first)

Respond only in JSON format:
{
  "vuln_statements": [
    {
      "vuln_file": "<file path>",
      "stmt_text": "<EXACT statement text copied from pre-fix code lines, no changes allowed>",
      "location": "hunk | context",
      "explanation": "<explanation linking this statement to the root cause>"
    }
  ]
}
"""


def get_vuln_stmt_final_prompt(
    root_cause:      str,
    first_evidence:  list,
    second_evidence: list,
) -> list:
    """3.5 综合判定漏洞语句。"""
    first_text = "\n".join(
        f"  Hunk {e['hunk_index']} | {e['file_path']}:{e['lineno']} | "
        f"stmt: \"{e['content']}\" | intent: {e['intent']} | rationale: {e['rationale']}"
        for e in first_evidence
    )
    second_text = "\n".join(
        f"  [{e['symbol']}] relevance={e['relevance_score']:.2f} | {e['rationale']}\n"
        f"  snippet: {e['snippet'][:200]}"
        for e in second_evidence
    )

    user_content = f"""\
## Vulnerability Root Cause
{root_cause}

## First Evidence Set (pre-fix code lines from hunks)
{first_text if first_text else '  (none)'}

## Second Evidence Set (suspect context snippets)
{second_text if second_text else '  (none)'}

Determine the vulnerable statement.
"""
    return [
        {"role": "system", "content": VULN_STMT_FINAL_SYSTEM},
        {"role": "user",   "content": user_content},
    ]


# ══════════════════════════════════════════════════════════════
# 11. BICAgent - 4.3 commit级漏洞存在性判定
# ══════════════════════════════════════════════════════════════

BIC_DETERMINATION_SYSTEM = """\
You are a Linux kernel vulnerability analyst performing commit-level vulnerability tracing.

Given the vulnerability root cause and a function body from a specific commit, answer:

Question 0 (sufficient): Is the provided code sufficient to make a determination?
- YES if the function body shows the relevant logic clearly
- NO if critical context is missing and a larger view is needed

Question 1 (has_bug): Does this function contain the vulnerable construct?
- YES if the vulnerable function/logic/statement IS PRESENT and the root cause condition exists
- NO if the vulnerable construct is ABSENT or the code already has correct handling

Question 2 (is_fixed): Does this function already contain the fix?
- YES if the code already has the correct handling that prevents the vulnerability
- NO if the fix is not yet present

A commit is a Bug-Introducing Commit when: has_bug=true AND is_fixed=false

IMPORTANT: If the vulnerable function or statement is completely absent, set has_bug=false.
Only set sufficient=false when you genuinely cannot tell from the shown code.

Respond only in JSON format:
{
  "sufficient": true or false,
  "has_bug": true or false,
  "is_fixed": true or false,
  "reason": "detailed explanation quoting specific lines from the snippet"
}
"""


def get_bic_determination_prompt(
    root_cause:    str,
    commit_hash:   str,
    file_path:     str,
    lineno:        int,
    code_snippet:  str,
    context_type:  str,
    commit_message: str,
) -> list:
    if context_type == "diff":
        context_label = f"Commit Diff ({file_path})"
        context_note  = "This is the diff introduced by this commit. Set sufficient=false if the diff alone is not enough to determine vulnerability."
    else:
        context_label = f"Function Body ({file_path}:{lineno})"
        context_note  = "This is the complete function body containing the vulnerable line."

    user_content = f"""\
## Vulnerability Root Cause
{root_cause}

## Commit: {commit_hash[:12]}
Message: {commit_message[:200]}

## {context_label}
{context_note}

{code_snippet}

Answer the questions about this commit version.
"""
    return [
        {"role": "system", "content": BIC_DETERMINATION_SYSTEM},
        {"role": "user",   "content": user_content},
    ]
