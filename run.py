
"""
run.py
─────────────────────────────────────────────
批量运行入口。
支持：
  - 全量运行（默认）
  - 指定起始索引断点续跑
  - 限制条数（调试用）
  - 并发数控制

运行示例：
  python run.py                        # 全量跑
  python run.py --start 100            # 从第100条开始续跑
  python run.py --limit 10             # 只跑前10条（调试）
  python run.py --start 100 --limit 50 # 从100开始跑50条
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data_types import DatasetEntry
from llm import Client, APIUnavailableError
from pipeline import Pipeline, save_state
from constants import DS_KVIC_PATH, SAVE_LOGS_DIR


def load_dataset(path: str) -> List[DatasetEntry]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    entries = []
    for d in data:
        # 兼容旧格式（单个 fix_commit_hash）和新格式（fix_commit_hashes 列表）
        if "fix_commit_hashes" in d:
            hashes = d["fix_commit_hashes"]
        else:
            hashes = [d["fix_commit_hash"]]
        entries.append(DatasetEntry(
            cveid=             d["cveid"],
            repo_name=         d["repo_name"],
            fix_commit_hashes= hashes,
            bug_commit_hash=   d["bug_commit_hash"],
        ))
    return entries


def make_save_dir(model: str) -> str:
    """根据模型名生成存储目录，避免不同模型结果互相覆盖。"""
    # 把模型名里的特殊字符换成下划线，作为目录后缀
    slug = model.replace("/", "_").replace(":", "_").replace(".", "-")
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, f"save_logs_{slug}")


def already_done(entry: DatasetEntry, save_dir: str) -> bool:
    """检查该条目是否已经有结果文件，用于断点续跑。"""
    log_dir = os.path.join(save_dir, entry.repo_name, entry.fix_commit_hash)
    return os.path.exists(os.path.join(log_dir, "result.json"))


def run_single(entry: DatasetEntry, pipeline: Pipeline, save_dir: str) -> dict:
    """运行单条，返回简要结果 dict。"""
    t0      = time.time()
    state   = pipeline.run(entry)
    elapsed = time.time() - t0

    save_state(state, base_dir=save_dir)

    correct = entry.bug_commit_hash in state.final_bic
    return {
        "cveid":   entry.cveid,
        "correct": correct,
        "bic":     state.final_bic,
        "truth":   entry.bug_commit_hash,
        "error":   bool(state.error),
        "elapsed": round(elapsed, 1),
    }


def run_batch(
    entries:     List[DatasetEntry],
    model:       str,
    save_dir:    str,
    workers:     int  = 1,
    skip_done:   bool = True,
    start_index: int  = 0,
) -> List[dict]:
    """
    批量运行。
    workers=1 时串行，workers>1 时并发（每线程独立 Client）。
    """
    os.makedirs(save_dir, exist_ok=True)
    print(f"模型: {model}")
    print(f"存储目录: {save_dir}")

    # 过滤已完成
    if skip_done:
        todo = [e for e in entries if not already_done(e, save_dir)]
        print(f"待运行: {len(todo)} / {len(entries)}（已完成 {len(entries)-len(todo)} 条）")
    else:
        todo = entries

    results    = []
    correct_cnt = 0
    error_cnt   = 0

    if workers == 1:
        # 串行
        client   = Client(model=model)
        pipeline = Pipeline(client)
        for i, entry in enumerate(todo, 1):
            print(f"\n[{i}/{len(todo)}] {entry.cveid}")
            try:
                r = run_single(entry, pipeline, save_dir)
            except APIUnavailableError as e:
                checkpoint = start_index + i - 1
                checkpoint_file = os.path.join(save_dir, "checkpoint.txt")
                with open(checkpoint_file, "w") as f:
                    f.write(str(checkpoint))
                print(f"\n[!] API 不可用: {e}")
                print(f"[!] 断点已保存: 第 {checkpoint} 条（{entry.cveid}），"
                      f"下次用 --start {checkpoint} 续跑")
                sys.exit(1)
            results.append(r)
            if r["correct"]: correct_cnt += 1
            if r["error"]:   error_cnt   += 1
            acc = correct_cnt / len(results) * 100
            print(f"  结果: {'✓' if r['correct'] else '✗'}  "
                  f"累计准确率: {acc:.1f}%  耗时: {r['elapsed']}s")
    else:
        # 并发（每个线程独立 Client 实例，避免共享状态）
        def worker(entry):
            c = Client(model=model)
            p = Pipeline(c)
            return run_single(entry, p, save_dir)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(worker, e): e for e in todo}
            for i, future in enumerate(as_completed(futures), 1):
                r = future.result()
                results.append(r)
                if r["correct"]: correct_cnt += 1
                if r["error"]:   error_cnt   += 1
                acc = correct_cnt / len(results) * 100
                print(f"[{i}/{len(todo)}] {r['cveid']} "
                      f"{'✓' if r['correct'] else '✗'}  "
                      f"累计准确率: {acc:.1f}%")

    print(f"\n{'='*60}")
    print(f"完成: {len(results)}  正确: {correct_cnt}  错误: {error_cnt}")
    if results:
        print(f"准确率: {correct_cnt/len(results)*100:.2f}%")

    return results


def main():
    parser = argparse.ArgumentParser(description="LLM4SZZ 批量运行")
    parser.add_argument("--model",   type=str, default=os.environ.get("MODEL_NAME", "gpt-4o"),
                        help="使用的模型名，例如: gpt-4o / gpt-4o-mini / "
                             "gemini-2.0-flash-preview / claude-3-5-haiku-20241022")
    parser.add_argument("--start",   type=int, default=0,
                        help="起始索引（断点续跑）")
    parser.add_argument("--limit",   type=int, default=None,
                        help="最多运行条数（调试用）")
    parser.add_argument("--workers", type=int, default=4,
                        help="并发线程数（默认4）")
    parser.add_argument("--no-skip", action="store_true",
                        help="不跳过已完成条目，强制重跑")
    parser.add_argument("--dataset", type=str, default=DS_KVIC_PATH,
                        help="数据集路径")
    parser.add_argument("--save-dir", type=str, default="",
                        help="自定义结果存储目录（默认根据模型名自动生成）")
    args = parser.parse_args()

    save_dir = args.save_dir or make_save_dir(args.model)

    entries = load_dataset(args.dataset)
    print(f"数据集: {len(entries)} 条")

    start = args.start
    end   = (start + args.limit) if args.limit else len(entries)
    entries = entries[start:end]
    print(f"运行范围: [{start}, {end})  共 {len(entries)} 条")

    run_batch(
        entries,
        model=args.model,
        save_dir=save_dir,
        workers=args.workers,
        skip_done=not args.no_skip,
        start_index=start,
    )


if __name__ == "__main__":
    main()
