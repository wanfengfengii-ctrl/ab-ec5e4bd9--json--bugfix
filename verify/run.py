"""一次性验证服务入口：构建检查 + 单元测试 + 端到端冒烟，退出码按位汇总。

退出码位含义（可组合）：
    0 = 全部通过
    1 = 构建检查失败（语法/导入）
    2 = 单元测试失败
    4 = 冒烟测试失败（签名 / 压缩 / 并发防重放等）

用法：
    python -m verify.run                 # 本地：构建检查 + 单元测试
    GATEWAY_URL=http://localhost:8080 python -m verify.run   # 附加冒烟
"""
from __future__ import annotations

import os
import sys
import time
import unittest
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

EXIT_BUILD = 1
EXIT_UNIT = 2
EXIT_SMOKE = 4


def check_build() -> bool:
    """构建检查：全部源文件可编译（语法正确）且关键模块可导入。"""
    print("[verify] 构建检查：编译全部 Python 源文件 ...")
    ok = True
    for sub in ("app", "verify", "tests"):
        for path in sorted((REPO_ROOT / sub).rglob("*.py")):
            try:
                source = path.read_text(encoding="utf-8")
                compile(source, str(path), "exec")
            except SyntaxError as exc:
                print(f"[verify]   语法错误 {path}: {exc}")
                ok = False
    if not ok:
        return False
    try:
        import app.auth  # noqa: F401
        import app.keystore  # noqa: F401
        import app.payload  # noqa: F401
        import app.server  # noqa: F401
        import app.store  # noqa: F401
        import verify.smoke  # noqa: F401
    except Exception as exc:
        print(f"[verify]   模块导入失败: {exc}")
        return False
    print("[verify]   构建检查通过")
    return True


def run_unit_tests() -> bool:
    print("[verify] 单元测试 ...")
    suite = unittest.TestLoader().discover(str(REPO_ROOT / "tests"),
                                           top_level_dir=str(REPO_ROOT))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.wasSuccessful()


def wait_healthy(base_url: str, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base_url + "/healthz", timeout=3) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


def main() -> int:
    exit_code = 0
    summary: dict[str, bool] = {}

    ok = check_build()
    summary["构建检查"] = ok
    exit_code |= 0 if ok else EXIT_BUILD

    ok = run_unit_tests()
    summary["单元测试"] = ok
    exit_code |= 0 if ok else EXIT_UNIT

    gateway = os.environ.get("GATEWAY_URL", "").rstrip("/")
    if gateway:
        keys_file = os.environ.get("KEYS_FILE",
                                   str(REPO_ROOT / "keys" / "keys.json"))
        if not wait_healthy(gateway):
            print(f"[verify] 网关 {gateway} 健康检查超时")
            ok = False
        else:
            print(f"[verify] 冒烟测试 -> {gateway} ...")
            from verify.smoke import run_smoke
            ok = run_smoke(gateway, keys_file)
        summary["冒烟测试"] = ok
        exit_code |= 0 if ok else EXIT_SMOKE
    else:
        print("[verify] 未设置 GATEWAY_URL，跳过冒烟测试")

    print("[verify] ====== 汇总 ======")
    for name, passed in summary.items():
        print(f"[verify]   {name}: {'通过' if passed else '失败'}")
    print(f"[verify] 退出码 {exit_code}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
