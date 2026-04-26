# MAS-SZZ: Multi-Agentic SZZ Algorithm for Vulnerability-Inducing Commit Identification
多智能体漏洞引入提交识别框架

给定 CVE 修复提交（VFC），由多智能体协作完成三阶段分析，自动定位漏洞引入提交（VIC）。

## 项目架构

- **阶段 1：根因分析** — Auditor 生成漏洞根因描述，Judge 验证质量，最多重试 3 次
- **阶段 2：锚点语句选择** — 解析 patch hunk，按改动意图分组，过滤非安全相关改动，定位最直接引入漏洞的代码行
- **阶段 3：自主仓库探索** — 以锚点行为起点，迭代 `git blame` 回溯，LLM 逐步判断每个历史 commit 是否存在漏洞，直到定位 VIC

## 目录结构

```
mas-szz/
├── run.py              # 批量运行入口
├── pipeline.py         # 主控流，串联三个阶段
├── data_types.py       # 全局数据结构定义
├── prompts.py          # 所有 Agent 的 prompt 模板
├── llm.py              # LLM 客户端（API key 和 base_url 在此配置）
├── constants.py        # 超参数配置（MODEL_NAME 等）
├── agents/
│   ├── root_cause_agent.py         # 阶段1 Auditor
│   ├── root_cause_reviewer.py      # 阶段1 Judge
│   ├── grouping_agent.py           # 阶段2 hunk 意图分析与分组
│   ├── reviewer_agent.py           # 阶段2 一致性审查 + 漏洞相关性筛选
│   ├── vuln_statement_agent.py     # 阶段2 定位锚点行
│   └── bic_agent.py                # 阶段3 git blame 回溯，定位 VIC
├── tools/              # git 操作、patch 解析、上下文提取
└── dataset/
```

## 数据集

两个数据集均为 JSON 数组，每条记录格式如下：

```json
{
  "cveid": "CVE-2021-12345",
  "repo_name": "torvalds/linux",
  "fix_commit_hashes": ["abc123..."],
  "bug_commit_hash": "def456..."
}
```

`bug_commit_hash` 为 ground truth VIC，用于评估准确率。切换数据集只需修改 `constants.py` 中的 `DS_KVIC_PATH` 和 `CVE_DESC_PATH`。

## 安装

```bash
pip install openai tiktoken
```

## 准备

将目标仓库 clone 到 `repos/<repo_name>/`（与数据集中 `repo_name` 字段一致）。

在 `llm.py` 的 `_API_CONFIGS` 中填写 API key 和 base_url，在 `constants.py` 中设置 `MODEL_NAME`。

## 运行

```bash
python run.py
```
