import re
import subprocess
from typing import List, Optional, Tuple


def get_file_content(repo_path: str, commit: str, file_path: str) -> str:
    """获取指定 commit 下文件内容，自动追踪文件重命名历史。"""
    content = _git_show_file(repo_path, commit, file_path)
    if content:
        return content
    try:
        out = subprocess.check_output(
            f"git log --follow --name-only --pretty='' -- {file_path}",
            shell=True, cwd=repo_path, stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore")
    except Exception:
        return ""
    for name in out.split("\n"):
        name = name.strip()
        if name and name != file_path:
            c = _git_show_file(repo_path, commit, name)
            if c:
                return c
    return ""


def _git_show_file(repo_path: str, commit: str, file_path: str) -> str:
    try:
        return subprocess.check_output(
            f"git show {commit}:{file_path}",
            shell=True, cwd=repo_path, stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def git_blame_line(
    repo_path: str,
    commit:    str,
    file_path: str,
    lineno:    int,
) -> Tuple[Optional[str], Optional[int]]:
    """
    对指定 commit 下 file_path 第 lineno 行执行 git blame。
    返回 (commit_hash, orig_lineno)，失败返回 (None, None)。
    """
    try:
        out = subprocess.check_output(
            f"git blame -L {lineno},{lineno} --porcelain {commit} -- {file_path}",
            shell=True, cwd=repo_path, stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore")
        for line in out.split("\n"):
            m = re.match(r"^([0-9a-f]{40}) (\d+) \d+", line)
            if m:
                return m.group(1), int(m.group(2))
    except Exception:
        pass
    return None, None


def get_commit_message(repo_path: str, commit: str) -> str:
    try:
        return subprocess.check_output(
            f"git log -1 --pretty=%B {commit}",
            shell=True, cwd=repo_path, stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def get_file_diff_at_commit(repo_path: str, commit: str, file_path: str) -> str:
    try:
        return subprocess.check_output(
            f"git show {commit} -- {file_path}",
            shell=True, cwd=repo_path, stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def get_function_at_commit(
    repo_path: str,
    commit:    str,
    file_path: str,
    lineno:    int,
) -> str:
    """提取 commit 版本中包含 lineno 行的完整函数体，返回带行号的字符串。"""
    content = get_file_content(repo_path, commit, file_path)
    if not content:
        return ""
    lines = content.split("\n")
    n = len(lines)
    lineno = min(max(lineno, 1), n)
    idx = lineno - 1  # 0-based

    # 向上找函数起点：首列非空白、非注释、非预处理行
    func_start = idx
    for i in range(idx, -1, -1):
        line = lines[i]
        if not line:
            continue
        if line[0] not in (" ", "\t"):
            s = line.strip()
            if s and not s.startswith("#") and not s.startswith("/*") and not s.startswith("*"):
                func_start = i
                break

    # 向下找函数终点：花括号匹配
    brace_depth = 0
    func_end = n - 1
    found_open = False
    for i in range(func_start, n):
        for ch in lines[i]:
            if ch == "{":
                brace_depth += 1
                found_open = True
            elif ch == "}":
                brace_depth -= 1
        if found_open and brace_depth == 0:
            func_end = i
            break

    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(func_start, func_end + 1))


def get_parent_commit(repo_path: str, commit: str) -> Optional[str]:
    try:
        out = subprocess.check_output(
            f"git log --pretty=%P -1 {commit}",
            shell=True, cwd=repo_path, stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="ignore").strip()
        parents = out.split()
        return parents[0] if parents else None
    except Exception:
        return None
