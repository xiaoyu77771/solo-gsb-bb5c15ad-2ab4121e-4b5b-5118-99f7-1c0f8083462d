"""校正回执端到端测试：签发、签名载荷编码、常量时间校验。每个用例使用独立临时 SQLite 库。"""
from __future__ import annotations

import hashlib
import hmac
import json
import re

import pytest
from fastapi.testclient import TestClient

TEST_SECRET = "test-correction-receipt-secret"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CALIB_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("CORRECTION_RECEIPT_SECRET", TEST_SECRET)
    from app.main import app  # 环境变量设置后再导入

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def two_points(client):
    # bias：1000 → 1.0，2000 → 3.0
    make_observation(client, 1000.0, readings=[9.0, 9.1, 8.9, 20.0])
    make_observation(client, 2000.0, readings=[7.0, 7.1, 6.9])
    return client


@pytest.fixture()
def frozen_clock(two_points, monkeypatch):
    """冻结 service 的时钟：issued_at 变为确定值 1700000000500。"""
    import app.service as service_module

    monkeypatch.setattr(service_module.time, "time", lambda: 1_700_000_000.5)
    return two_points


def make_observation(client, ts, readings, reference=10.0, tolerance=0.5):
    resp = client.post(
        "/observations",
        json={"timestamp": ts, "reference": reference, "tolerance": tolerance, "readings": readings},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def issue(client, ts=1500.0, reading=5.0):
    resp = client.post("/correction-receipts", json={"timestamp": ts, "reading": reading})
    assert resp.status_code == 200, resp.text
    return resp.json()


def manual_receipt(secret, *, version, timestamp, reading, bias, corrected, issued_at):
    """按文档规则手工重算回执：固定键序、最短十进制、UTF-8 无空白、HMAC-SHA256 小写十六进制。"""
    payload = {
        "version": version,
        "timestamp": timestamp,
        "reading": reading,
        "bias": bias,
        "corrected": corrected,
        "issued_at": issued_at,
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()


# ---------- 签发 ----------

def test_issue_receipt_returns_signed_fields(two_points):
    body = issue(two_points)
    assert body["version"] == 1
    assert body["timestamp"] == pytest.approx(1500.0)   # 归一化请求：Unix 秒
    assert body["reading"] == pytest.approx(5.0)
    assert body["bias"] == pytest.approx(2.0)           # 复用漂移补偿：1.0 与 3.0 的中点
    assert body["corrected"] == pytest.approx(7.0)      # 读数 + 偏差
    assert isinstance(body["issued_at"], int)           # UTC Unix 毫秒整数
    assert re.fullmatch(r"[0-9a-f]{64}", body["receipt"])  # HMAC-SHA256 小写十六进制


def test_issue_receipt_issued_at_is_utc_unix_ms(frozen_clock):
    body = issue(frozen_clock)
    assert body["issued_at"] == 1700000000500


def test_issue_receipt_matches_manual_hmac(frozen_clock):
    body = issue(frozen_clock)
    expected = manual_receipt(
        TEST_SECRET,
        version=1, timestamp=1500.0, reading=5.0, bias=2.0, corrected=7.0,
        issued_at=1700000000500,
    )
    assert body["receipt"] == expected
    # 固定的已知答案：签名载荷编码与密钥任何意外改动都会让此断言失败
    assert body["receipt"] == "fa6416f722e4e50937742dceee036c117f8685482831d2a7cfeb1919a0de3969"


def test_issue_receipt_normalizes_iso8601_timestamp(frozen_clock):
    body = issue(frozen_clock, ts="1970-01-01T00:25:00Z")
    assert body["timestamp"] == pytest.approx(1500.0)   # 归一化为 Unix 秒
    # 签名针对归一化后的数值，而非原始字符串
    assert body["receipt"] == manual_receipt(
        TEST_SECRET,
        version=1, timestamp=1500.0, reading=5.0, bias=2.0, corrected=7.0,
        issued_at=1700000000500,
    )


def test_issue_receipt_reuses_drift_compensation(two_points):
    correction = two_points.post("/corrections", json={"timestamp": 1500.0, "reading": 5.0}).json()
    body = issue(two_points)
    assert body["bias"] == correction["bias"]
    assert body["corrected"] == correction["corrected"]


def test_issue_receipt_at_exact_observation_point(two_points):
    body = issue(two_points, ts=2000.0)
    assert body["bias"] == pytest.approx(3.0)
    assert body["corrected"] == pytest.approx(8.0)


def test_issue_receipt_outside_coverage_rejected(two_points):
    for ts in (999.0, 2001.0):
        resp = two_points.post("/correction-receipts", json={"timestamp": ts, "reading": 5.0})
        assert resp.status_code == 400
        assert "outside calibration coverage" in resp.json()["detail"]


def test_issue_receipt_without_any_observation_rejected(client):
    resp = client.post("/correction-receipts", json={"timestamp": 1.0, "reading": 5.0})
    assert resp.status_code == 400


def test_issue_receipt_missing_or_invalid_fields_rejected(two_points):
    assert two_points.post("/correction-receipts", json={"reading": 5.0}).status_code == 422
    assert two_points.post("/correction-receipts", json={"timestamp": 1500.0}).status_code == 422
    resp = two_points.post("/correction-receipts",
                           json={"timestamp": "not-a-timestamp", "reading": 5.0})
    assert resp.status_code == 422


# ---------- 校验 ----------

def test_verify_round_trip_valid(two_points):
    body = issue(two_points)
    resp = two_points.post("/correction-receipts/verify", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"valid": True}


@pytest.mark.parametrize("field,tampered", [
    ("version", 2),
    ("timestamp", 1500.5),
    ("reading", 5.5),
    ("bias", 2.5),
    ("corrected", 7.5),
    ("issued_at", 1700000000501),
])
def test_verify_tampered_signed_field_invalid(frozen_clock, field, tampered):
    body = issue(frozen_clock)
    body[field] = tampered
    resp = frozen_clock.post("/correction-receipts/verify", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"valid": False}


def test_verify_tampered_receipt_invalid(two_points):
    body = issue(two_points)
    body["receipt"] = "0" * 64
    resp = two_points.post("/correction-receipts/verify", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"valid": False}


def test_verify_receipt_with_non_hex_characters_invalid(two_points):
    body = issue(two_points)
    body["receipt"] = "not-a-hex-receipt"
    resp = two_points.post("/correction-receipts/verify", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"valid": False}


def test_verify_is_pure_signature_check_without_observations(client):
    # 校验不触碰数据库：无任何观测时，手工构造的有效回执仍应通过
    receipt = manual_receipt(
        TEST_SECRET,
        version=1, timestamp=1500.0, reading=5.0, bias=2.0, corrected=7.0,
        issued_at=1700000000500,
    )
    body = {
        "version": 1, "timestamp": 1500.0, "reading": 5.0,
        "bias": 2.0, "corrected": 7.0, "issued_at": 1700000000500,
        "receipt": receipt,
    }
    resp = client.post("/correction-receipts/verify", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"valid": True}


def test_verify_fails_after_secret_rotation(client, two_points, monkeypatch):
    body = issue(two_points)
    monkeypatch.setenv("CORRECTION_RECEIPT_SECRET", "rotated-secret")
    resp = two_points.post("/correction-receipts/verify", json=body)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"valid": False}


@pytest.mark.parametrize("field", [
    "version", "timestamp", "reading", "bias", "corrected", "issued_at", "receipt",
])
def test_verify_missing_field_rejected(two_points, field):
    body = issue(two_points)
    del body[field]
    assert two_points.post("/correction-receipts/verify", json=body).status_code == 422


@pytest.mark.parametrize("field,tampered", [
    ("version", "one"),
    ("timestamp", "not-a-timestamp"),
    ("reading", "abc"),
    ("bias", [2.0]),
    ("corrected", {"value": 7.0}),
    ("issued_at", "soon"),
    ("issued_at", 1700000000500.5),
    ("receipt", 12345),
])
def test_verify_wrong_type_rejected(two_points, field, tampered):
    body = issue(two_points)
    body[field] = tampered
    assert two_points.post("/correction-receipts/verify", json=body).status_code == 422


def test_verify_non_object_body_rejected(two_points):
    assert two_points.post("/correction-receipts/verify", json=[1, 2, 3]).status_code == 422


# ---------- 密钥来源 ----------

def test_dev_default_secret_used_when_env_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("CALIB_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.delenv("CORRECTION_RECEIPT_SECRET", raising=False)
    from app.main import app

    with TestClient(app) as client:
        make_observation(client, 1000.0, readings=[9.0, 9.1, 8.9, 20.0])
        make_observation(client, 2000.0, readings=[7.0, 7.1, 6.9])
        body = issue(client)
        # 缺省密钥即 docker-compose 提供的开发默认值
        assert body["receipt"] == manual_receipt(
            "dev-correction-receipt-secret",
            version=1, timestamp=1500.0, reading=5.0, bias=2.0, corrected=7.0,
            issued_at=body["issued_at"],
        )
        resp = client.post("/correction-receipts/verify", json=body)
        assert resp.json() == {"valid": True}
