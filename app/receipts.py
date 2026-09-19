"""校正回执：签名载荷编码、HMAC-SHA256 签发与常量时间校验。

纯函数模块，不触碰数据库，便于单测。签名载荷按 version、timestamp、reading、
bias、corrected、issued_at 的固定字段顺序，以 JSON 数值最短十进制（json 默认的
最短往返表示）、UTF-8、无空白编码；密钥读取环境变量 CORRECTION_RECEIPT_SECRET，
缺省或为空时回退到仅供本地开发的内置默认值（与 docker-compose 的开发默认值一致）。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os

RECEIPT_VERSION = 1

# 仅供本地开发的缺省密钥；生产环境必须经 CORRECTION_RECEIPT_SECRET 覆盖
DEFAULT_RECEIPT_SECRET = "dev-correction-receipt-secret"


def receipt_secret() -> str:
    """签名密钥：环境变量 CORRECTION_RECEIPT_SECRET，缺省或空串时回退开发默认值。"""
    return os.environ.get("CORRECTION_RECEIPT_SECRET") or DEFAULT_RECEIPT_SECRET


def signature_payload(
    version: int, timestamp: float, reading: float, bias: float, corrected: float, issued_at: int
) -> bytes:
    """按固定字段顺序把签名字段编码为待签名字节串。

    JSON 对象键序固定为 version、timestamp、reading、bias、corrected、issued_at；
    数值按最短十进制（json 默认的最短往返表示）、UTF-8、无空白
    （separators=(",", ":")）编码。
    """
    payload = {
        "version": version,
        "timestamp": timestamp,
        "reading": reading,
        "bias": bias,
        "corrected": corrected,
        "issued_at": issued_at,
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_receipt(
    version: int, timestamp: float, reading: float, bias: float, corrected: float, issued_at: int
) -> str:
    """对签名载荷计算 HMAC-SHA256，返回小写十六进制回执。"""
    payload = signature_payload(version, timestamp, reading, bias, corrected, issued_at)
    return hmac.new(receipt_secret().encode("utf-8"), payload, hashlib.sha256).hexdigest()


def constant_time_equal(expected: str, candidate: str) -> bool:
    """常量时间比较两个回执字符串（按 UTF-8 字节比较，候选可含任意字符）。"""
    return hmac.compare_digest(expected.encode("utf-8"), candidate.encode("utf-8"))
