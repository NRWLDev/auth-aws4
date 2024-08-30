from unittest import mock

from freezegun import freeze_time

import aws4
from aws4.client import HttpxAWS4Auth
from aws4.key_pair import KeyPair


def test_eq():
    kp1 = KeyPair("access-key-id", "secret-access-key")
    kp2 = KeyPair("access-key", "secret-access")
    auth1 = HttpxAWS4Auth(kp1, "service", "region")
    auth2 = HttpxAWS4Auth(kp1, "service", "region")
    auth3 = HttpxAWS4Auth(kp2, "service", "region")

    assert auth1 == auth2
    assert auth1 != auth3


@freeze_time("2024-01-02T03:04")
def test_http_request(monkeypatch):
    monkeypatch.setattr(aws4, "generate_signature", mock.Mock(return_value="signature"))

    kp = KeyPair("access-key-id", "secret-access-key")
    auth = HttpxAWS4Auth(kp, "service", "region")

    request = mock.Mock(
        method="POST",
        headers={},
        content=b"content",
        url=mock.Mock(netloc=b"hostname", query="", path="/path", scheme="http"),
    )
    request = next(auth.auth_flow(request))

    assert request.headers == {
        "x-amz-date": "20240102T030400Z",
        "host": "hostname",
        "Authorization": "AWS4-HMAC-SHA256 Credential=access-key-id/20240102/region/service/aws4_request, SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date, Signature=signature",
        "x-amz-content-sha256": "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73",
        "Content-Length": "7",
    }


@freeze_time("2024-01-02T03:04")
def test_https_request(monkeypatch):
    monkeypatch.setattr(aws4, "generate_signature", mock.Mock(return_value="signature"))

    kp = KeyPair("access-key-id", "secret-access-key")
    auth = HttpxAWS4Auth(kp, "service", "region")

    request = mock.Mock(
        method="GET",
        headers={},
        content=b"",
        url=mock.Mock(netloc=b"hostname", query="", path="/path", scheme="https"),
    )
    request = next(auth.auth_flow(request))

    assert request.headers == {
        "x-amz-date": "20240102T030400Z",
        "host": "hostname",
        "Authorization": "AWS4-HMAC-SHA256 Credential=access-key-id/20240102/region/service/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=signature",
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
    }


@freeze_time("2024-01-02T03:04")
def test_body_request(monkeypatch):
    monkeypatch.setattr(aws4, "generate_signature", mock.Mock(return_value="signature"))

    kp = KeyPair("access-key-id", "secret-access-key")
    auth = HttpxAWS4Auth(kp, "service", "region")

    request = mock.Mock(
        method="POST",
        headers={},
        content=b"content",
        url=mock.Mock(netloc=b"hostname", query="", path="/path", scheme="https"),
    )
    request = next(auth.auth_flow(request))

    assert request.headers == {
        "x-amz-date": "20240102T030400Z",
        "host": "hostname",
        "Authorization": "AWS4-HMAC-SHA256 Credential=access-key-id/20240102/region/service/aws4_request, SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date, Signature=signature",
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        "Content-Length": "7",
    }
