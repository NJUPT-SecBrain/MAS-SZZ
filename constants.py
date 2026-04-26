import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_DIR      = os.path.join(BASE_DIR, "dataset")
DS_KVIC_PATH     = os.path.join(DATASET_DIR, "DS_VSZZ_per_fix.json")
CVE_DESC_PATH    = os.path.join(DATASET_DIR, "cve_descriptions_vszz.json")  # 切换数据集改这里：cve_descriptions_java.json

REPOS_DIR        = os.path.join(BASE_DIR, "repos")
SAVE_LOGS_DIR    = os.path.join(BASE_DIR, "save_logs_vszz2")

MODEL_NAME       = "gpt-4o"
MAX_TOKENS       = 2048
TEMPERATURE      = 0.2        # 低温，输出更稳定
MAX_HISTORY_CHARS = 30000     # 超出时从头部裁剪历史消息
MAX_ROOT_CAUSE_RETRIES = 3
