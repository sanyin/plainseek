"""pseek —— CTF 一条龙解密工具包。

模块划分
--------
oracles     格式验证器：自动判断"解出来的东西对不对"
alphabets   字符表（密码表）识别与还原，支持密码表被改动的情况
ciphers     RC4 家族 / DES 变体 / AES / TEA / PRNG 等参数化实现
transforms  编码、压缩、位运算等可插拔变换 + 链式配方解析
recover     已知明文、密钥恢复、暴力破解辅助
search      链式搜索引擎：多层加密自动叠加还原
"""

__version__ = "0.1.0"
