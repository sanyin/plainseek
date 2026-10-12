"""验证 --crib：当最后一层解出来"不像任何已知格式"时，crib 是唯一的判据。"""
import base64
import os
import shutil
import sys
import tempfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dkit import pipeline

payload = b"\x00\x01\x02CRIB_SECRET_MARKER\x03\x04\x05" + os.urandom(32)
data = base64.b64encode(zlib.compress(payload))
tmp = tempfile.mkdtemp(prefix="autocrypt_crib_")
try:
    with open(os.path.join(tmp, "blob.bin"), "wb") as fh:
        fh.write(data)
    print("--- 不给 crib ---")
    rep = pipeline.run([tmp], pipeline.Options(timeout=30, log=lambda m: None))
    print("   解出结果数:", len(rep.outcomes))
    print("--- 给 crib 'CRIB_SECRET_MARKER' ---")
    rep2 = pipeline.run([tmp], pipeline.Options(timeout=30, crib="CRIB_SECRET_MARKER",
                                               log=lambda m: None))
    for o in rep2.outcomes:
        print("   命中:", o.summary()[:110])
    ok = bool(rep2.outcomes) and o2 if False else bool(rep2.outcomes) and \
        b"CRIB_SECRET_MARKER" in rep2.outcomes[0].plaintext
    print("   [PASS] crib 生效，精确剜出目标层" if ok else "   [FAIL]")
finally:
    shutil.rmtree(tmp, ignore_errors=True)
