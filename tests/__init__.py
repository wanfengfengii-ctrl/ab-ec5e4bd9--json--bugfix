import sys
from pathlib import Path

# 保证从仓库根目录导入 app 包（无论以何种方式发现测试）
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
