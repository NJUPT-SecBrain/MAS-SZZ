from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class DatasetEntry:
    cveid:             str
    repo_name:         str
    fix_commit_hashes: List[str]
    bug_commit_hash:   str

    @property
    def fix_commit_hash(self) -> str:
        """返回第一个 fix commit，兼容单 commit 旧格式。"""
        return self.fix_commit_hashes[0] if self.fix_commit_hashes else ""


@dataclass
class RootCause:
    text:            str
    evidence_points: str          = ""
    passed_review:   Optional[bool] = None
    feedback:        str          = ""


@dataclass
class HunkRecord:
    hunk_index:            int
    file_path:             str
    raw_str:               str
    fix_commit:            str         = ""
    supplemental_context:  str         = ""
    deleted_lines:         List[tuple] = field(default_factory=list)
    added_lines:           List[tuple] = field(default_factory=list)
    context_lines:         List[tuple] = field(default_factory=list)  # [(old_lineno, new_lineno, content)]


@dataclass
class VulnStatement:
    file_path:   str
    lineno:      int
    content:     str
    hunk_index:  int
    fix_commit:  str   = ""
    confidence:  float = 1.0


@dataclass
class PipelineState:
    entry:              DatasetEntry

    # 阶段 1
    cve_description:    str                 = ""
    patch_content:      str                 = ""
    commit_message:     str                 = ""
    root_cause:         Optional[RootCause] = None

    # 阶段 2
    hunks:              List[HunkRecord]    = field(default_factory=list)

    # 阶段 3
    vuln_statements:    List[VulnStatement] = field(default_factory=list)

    # 阶段 4
    final_bic:          List[str]           = field(default_factory=list)

    used_fallback:      bool  = False
    error:              str   = ""
    llm_call_count:     int   = 0
    llm_token_count:    int   = 0
    log_msgs:           List  = field(default_factory=list)

    @property
    def cveid(self) -> str:
        return self.entry.cveid

    @property
    def repo_name(self) -> str:
        return self.entry.repo_name

    @property
    def fix_commit_hashes(self) -> List[str]:
        return self.entry.fix_commit_hashes

    @property
    def fix_commit_hash(self) -> str:
        return self.entry.fix_commit_hash

    @property
    def ground_truth_bic(self) -> str:
        return self.entry.bug_commit_hash
