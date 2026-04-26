"""
tools/context_retriever.py
─────────────────────────────────────────────
当 hunk 语义不完整时，根据缺失信息列表从代码仓库中
自动定位并提取补充代码片段。

支持提取：
  - 函数体定义
  - 变量 / 类型 / 结构体定义
  - 宏定义
  - 指定行号的上下文窗口
"""

import re
import subprocess
from typing import List, Optional
from data_types import HunkRecord


def retrieve_context(
    hunk:       HunkRecord,
    missing:    List[str],
    repo_path:  str,
    commit:     str,
    context_lines: int = 10,
) -> str:
    """
    根据缺失信息列表从仓库提取补充代码片段。

    hunk       : 需要补充语义的 hunk
    missing    : SemanticCompletenessAgent 输出的缺失信息列表
    repo_path  : 本地 git 仓库路径
    commit     : fix commit hash（在此版本下查找）
    返回：拼接好的补充上下文字符串
    """
    file_content = _get_file_at_commit(repo_path, commit, hunk.file_path)
    if not file_content:
        return ""

    file_lines = file_content.split("\n")
    snippets   = []

    for item in missing:
        item_lower = item.lower()

        # 从缺失描述里提取符号名
        symbols = _extract_symbols(item)

        for symbol in symbols:
            snippet = None

            if any(k in item_lower for k in ["function", "func", "函数"]):
                snippet = _find_function(file_lines, symbol)

            elif any(k in item_lower for k in ["macro", "宏", "#define"]):
                snippet = _find_macro(file_lines, symbol)

            elif any(k in item_lower for k in ["struct", "结构体", "type", "typedef"]):
                snippet = _find_struct_or_type(file_lines, symbol)

            elif any(k in item_lower for k in ["variable", "变量", "declaration", "声明"]):
                snippet = _find_variable(file_lines, symbol)

            # 兜底：搜索符号名附近的上下文窗口
            if not snippet:
                snippet = _find_symbol_context(file_lines, symbol, context_lines)

            if snippet:
                snippets.append(f"/* {symbol} */\n{snippet}")

    # 如果所有符号都没找到，提取 hunk 删除行附近的上下文
    if not snippets and hunk.deleted_lines:
        first_lineno = hunk.deleted_lines[0][0]
        snippets.append(_get_line_window(file_lines, first_lineno, context_lines))

    return "\n\n".join(snippets)


# ══════════════════════════════════════════════════════════════
# 内部工具函数
# ══════════════════════════════════════════════════════════════

def _get_file_at_commit(repo_path: str, commit: str, file_path: str) -> str:
    """用 git show 获取指定 commit 下的文件内容。"""
    try:
        return subprocess.check_output(
            f"git show {commit}:{file_path}",
            shell=True, cwd=repo_path,
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _extract_symbols(text: str) -> List[str]:
    """从缺失描述文本中提取符号名（驼峰、下划线命名）。"""
    # 匹配 C 风格标识符：字母/下划线开头，含字母数字下划线
    candidates = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\b", text)
    # 过滤常见英文停用词
    stopwords = {
        "the", "and", "for", "with", "this", "that", "from", "missing",
        "function", "variable", "struct", "macro", "define", "type",
        "declaration", "definition", "context", "information"
    }
    return [s for s in candidates if s.lower() not in stopwords]


def _find_function(lines: List[str], func_name: str) -> Optional[str]:
    """
    查找函数定义：匹配 `返回类型 func_name(` 形式。
    提取从函数签名到对应右花括号的完整函数体。
    """
    pattern = re.compile(rf"\b{re.escape(func_name)}\s*\(")
    start = None
    for i, line in enumerate(lines):
        if pattern.search(line) and not line.strip().startswith("//"):
            start = i
            break

    if start is None:
        return None

    # 向上找函数签名起始行（返回类型可能在上一行）
    sig_start = max(0, start - 2)

    # 向下找匹配的右花括号
    brace_count = 0
    end = start
    for i in range(start, min(start + 200, len(lines))):
        brace_count += lines[i].count("{") - lines[i].count("}")
        if brace_count > 0:
            end = i
        if brace_count == 0 and i > start:
            end = i
            break

    snippet_lines = lines[sig_start:end + 1]
    # 超过60行只取前30行
    if len(snippet_lines) > 60:
        snippet_lines = snippet_lines[:30] + ["    /* ... (truncated) ... */"]

    return "\n".join(snippet_lines)


def _find_macro(lines: List[str], macro_name: str) -> Optional[str]:
    """查找 #define MACRO_NAME ... 宏定义。"""
    pattern = re.compile(rf"^#define\s+{re.escape(macro_name)}\b")
    for i, line in enumerate(lines):
        if pattern.match(line.strip()):
            # 处理续行符 \
            result = [line]
            j = i + 1
            while line.rstrip().endswith("\\") and j < len(lines):
                line = lines[j]
                result.append(line)
                j += 1
            return "\n".join(result)
    return None


def _find_struct_or_type(lines: List[str], type_name: str) -> Optional[str]:
    """查找 struct/typedef 定义。"""
    pattern = re.compile(
        rf"\b(?:struct|typedef|enum)\s+.*{re.escape(type_name)}\b"
    )
    for i, line in enumerate(lines):
        if pattern.search(line):
            # 找到对应的右花括号
            brace_count = 0
            end = i
            for j in range(i, min(i + 100, len(lines))):
                brace_count += lines[j].count("{") - lines[j].count("}")
                end = j
                if brace_count < 0 or (brace_count == 0 and j > i and "{" in "".join(lines[i:j])):
                    break
            return "\n".join(lines[i:end + 2])
    return None


def _find_variable(lines: List[str], var_name: str) -> Optional[str]:
    """查找变量声明行。"""
    pattern = re.compile(rf"\b{re.escape(var_name)}\b")
    for line in lines:
        stripped = line.strip()
        if pattern.search(stripped) and not stripped.startswith("//"):
            if re.search(r"\b(int|long|char|void|bool|u8|u16|u32|u64|struct|enum)\b", stripped):
                return stripped
    return None


def _find_symbol_context(
    lines: List[str], symbol: str, window: int = 10
) -> Optional[str]:
    """在文件中搜索符号，返回其附近的代码窗口。"""
    pattern = re.compile(rf"\b{re.escape(symbol)}\b")
    for i, line in enumerate(lines):
        if pattern.search(line):
            start = max(0, i - window // 2)
            end   = min(len(lines), i + window // 2)
            return "\n".join(lines[start:end])
    return None


def _get_line_window(lines: List[str], lineno: int, window: int = 10) -> str:
    """返回指定行号附近的代码窗口（1-based）。"""
    idx   = lineno - 1
    start = max(0, idx - window)
    end   = min(len(lines), idx + window)
    return "\n".join(
        f"{start + i + 1}: {l}"
        for i, l in enumerate(lines[start:end])
    )
