"""
tools/patch_parser.py
─────────────────────────────────────────────
解析 git show / git diff 输出的 patch 文本，
拆成结构化的 HunkRecord 列表供后续 agent 使用。

输出结构：
  List[HunkRecord]
  每个 HunkRecord 包含：
    - hunk_index      : 序号
    - file_path       : 所属文件
    - raw_str         : hunk 原始文本
    - deleted_lines   : [(旧行号, 内容), ...]
    - added_lines     : [(新行号, 内容), ...]
"""

import re
from typing import List, Tuple
from data_types import HunkRecord


def parse_patch(patch_text: str) -> List[HunkRecord]:
    """
    解析完整 patch 文本，返回 HunkRecord 列表。
    """
    hunks = []
    hunk_index = 0

    # 按文件分割：diff --git a/... b/...
    file_blocks = re.split(r"(?=^diff --git )", patch_text, flags=re.MULTILINE)

    for block in file_blocks:
        if not block.strip():
            continue

        # 提取文件路径：+++ b/path
        file_path = _extract_file_path(block)
        if not file_path:
            continue

        # 按 @@ 分割 hunk
        hunk_blocks = re.split(r"(?=^@@)", block, flags=re.MULTILINE)
        for hb in hunk_blocks:
            if not hb.startswith("@@"):
                continue

            deleted, added, context = _parse_hunk_lines(hb)

            hunks.append(HunkRecord(
                hunk_index=hunk_index,
                file_path=file_path,
                raw_str=hb.strip(),
                deleted_lines=deleted,
                added_lines=added,
                context_lines=context,
            ))
            hunk_index += 1

    return hunks


def _extract_file_path(block: str) -> str:
    """从文件块中提取文件路径，优先用 +++ b/ 行。"""
    # +++ b/drivers/md/raid10.c
    match = re.search(r"^\+\+\+ b/(.+)$", block, re.MULTILINE)
    if match:
        return match.group(1).strip()

    # 兜底：diff --git a/x b/x
    match = re.search(r"^diff --git a/\S+ b/(\S+)", block, re.MULTILINE)
    if match:
        return match.group(1).strip()

    return ""


def _parse_hunk_lines(hunk_str: str) -> Tuple[List[Tuple], List[Tuple], List[Tuple]]:
    """
    解析单个 hunk，提取删除行、新增行和上下文行。
    返回：
      deleted_lines : [(旧行号, 行内容), ...]
      added_lines   : [(新行号, 行内容), ...]
      context_lines : [(旧行号, 新行号, 行内容), ...]
    """
    lines = hunk_str.split("\n")
    header = lines[0]
    old_start, new_start = _parse_hunk_header(header)

    deleted = []
    added   = []
    context = []
    old_lineno = old_start
    new_lineno = new_start

    for line in lines[1:]:
        if line.startswith("-") and not line.startswith("---"):
            deleted.append((old_lineno, line[1:]))
            old_lineno += 1
        elif line.startswith("+") and not line.startswith("+++"):
            added.append((new_lineno, line[1:]))
            new_lineno += 1
        else:
            # 上下文行，存精确行号
            context.append((old_lineno, new_lineno, line))
            old_lineno += 1
            new_lineno += 1

    return deleted, added, context


def _parse_hunk_header(header: str) -> Tuple[int, int]:
    """
    解析 @@ -a,b +c,d @@ 格式，返回 (old_start, new_start)。
    """
    match = re.search(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", header)
    if match:
        return int(match.group(1)), int(match.group(2))
    return 1, 1


def get_patch_summary(hunks: List[HunkRecord]) -> str:
    """
    生成 patch 的简要摘要，供日志和 prompt 使用。
    """
    total_del = sum(len(h.deleted_lines) for h in hunks)
    total_add = sum(len(h.added_lines)   for h in hunks)
    files     = list(dict.fromkeys(h.file_path for h in hunks))

    lines = [
        f"共 {len(hunks)} 个hunk，涉及 {len(files)} 个文件",
        f"删除行: {total_del}  新增行: {total_add}",
        "文件列表:",
    ]
    for f in files:
        lines.append(f"  - {f}")
    return "\n".join(lines)
