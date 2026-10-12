import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dkit import selftest

which = sys.argv[1] if len(sys.argv) > 1 else "all"
tests = {
    "1": selftest.test_oracles,
    "2": selftest.test_custom_table_rc4,
    "3": selftest.test_three_layers,
    "4": selftest.test_aes_known_key,
    "5": selftest.test_des_bitrev,
    "6": selftest.test_standard_rc4_custom_table,
}
for key, fn in tests.items():
    if which not in ("all", key):
        continue
    t0 = time.time()
    print(f"--- 开始测试 {key} ({fn.__name__})", flush=True)
    fn()
    print(f"--- 测试 {key} 用时 {time.time() - t0:.1f}s", flush=True)
