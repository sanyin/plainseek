import io
import os
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dkit import oracles
from PIL import Image

buf = io.BytesIO()
Image.new("RGB", (32, 32), (200, 30, 30)).save(buf, format="JPEG")
jpg = buf.getvalue()
png = io.BytesIO()
Image.new("RGB", (32, 32)).save(png, format="PNG")
png = png.getvalue()

print("jpeg ->", [str(v) for v in oracles.evaluate(jpg)])
print("png  ->", [str(v) for v in oracles.evaluate(png)])
print("gzip ->", [str(v) for v in oracles.evaluate(__import__("gzip").compress(b"hello world" * 20))])
print("flag ->", [str(v) for v in oracles.evaluate(b"....flag{abc_def_123}....")])
print("text ->", [str(v) for v in oracles.evaluate("这是一段中文说明文字，用于测试。".encode())])
print("b64  ->", [str(v) for v in oracles.evaluate(__import__("base64").b64encode(jpg))])
print("rand ->", [str(v) for v in oracles.evaluate(os.urandom(400))])
print("dht tables:", len(oracles.dht_tables(jpg)))
print("entropy rand:", round(oracles.entropy(os.urandom(4096)), 3))
print("quick jpg:", oracles.quick_score(jpg), "quick text:", oracles.quick_score(b"flag{test_flag_value}"))
print("describe:", oracles.describe(b"flag{test_flag_value}"))
