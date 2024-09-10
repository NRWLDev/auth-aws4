import datetime
from unittest import mock

import multidict
import pytest

from aws4 import (
    _generate_canonical_request_hash,
    _parse_authorization,
    _parse_key_date,
    _recreate_canonical_request_hash,
)


def test_parse_authorization():
    authorization = "AWS4-HMAC-SHA256 Credential=AKIA0SYLV9QT8A6LKRD6/20230809/ksa/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=297e52e0243a99ef3fd140f1c8a605593be6b742bd92b19a23acc97e0a2053bb"
    auth_type, credential, signed_headers, signature = _parse_authorization(authorization)
    assert auth_type == "AWS4-HMAC-SHA256"
    assert credential == "AKIA0SYLV9QT8A6LKRD6/20230809/ksa/iam/aws4_request"
    assert signed_headers == "host;x-amz-content-sha256;x-amz-date"
    assert signature == "297e52e0243a99ef3fd140f1c8a605593be6b742bd92b19a23acc97e0a2053bb"


@pytest.mark.parametrize(
    "drift",
    [10, -10],
)
def test_parse_key_date_drift(drift):
    timestamp = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=drift)).strftime(
        "%Y%m%dT%H%M%SZ",
    )
    headers = multidict.CIMultiDict(
        [
            ("host", "localhost:9004"),
            ("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("x-amz-date", timestamp),
        ],
    )

    with pytest.raises(Exception, match="Replay/drift detected in date."):
        _parse_key_date(headers)


def test_parse_key_date_missing():
    headers = multidict.CIMultiDict(
        [
            ("host", "localhost:9004"),
            ("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ],
    )

    with pytest.raises(Exception):  # noqa: B017, PT011
        _parse_key_date(headers)


def test_generate_canonical_request_hash():
    request_hash, signed_headers = _generate_canonical_request_hash(
        "GET",
        mock.Mock(path="/a/path", query=b"foo=bar"),
        {"foo": "hello    world", "BaZ": "wut", "Authorization": "xxx"},  # pragma: no-spell-check
        "content-sha-256",
    )

    assert request_hash == "2a7fc799f682d7c56c49803400da06065ac615b78d592424902b44505fb57cc1"
    assert signed_headers == "baz;foo"


def test_recreate_canonical_request_hash():
    request_hash = _recreate_canonical_request_hash(
        "GET",
        mock.Mock(path="/a/path", query=b"foo=bar"),
        {"foo": "hello    world", "BaZ": "wut", "Authorization": "xxx"},  # pragma: no-spell-check
        "baz;foo",
        "content-sha-256",
    )

    assert request_hash == "2a7fc799f682d7c56c49803400da06065ac615b78d592424902b44505fb57cc1"
