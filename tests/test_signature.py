from datetime import datetime, timedelta, timezone
from unittest import mock

import multidict
import pytest

import aws4


def test_to_utc_naive():
    dt = datetime(2023, 1, 2, 3, 4, 5, 12345)  # noqa: DTZ001
    utc = aws4._to_utc(dt)

    assert dt == utc


def test_to_utc_tz_aware():
    sgt_timedelta = timedelta(hours=5)
    sgt_tz = timezone(sgt_timedelta, name="SGT")
    dt = datetime(2023, 1, 2, 3, 4, 5, 12345, tzinfo=sgt_tz)
    utc = aws4._to_utc(dt)

    assert dt != utc
    assert utc == datetime(2023, 1, 1, 22, 4, 5, 12345, tzinfo=None)  # noqa: DTZ001


def test_to_amz_date():
    dt = datetime(2023, 1, 2, 3, 4, 5, 12345, tzinfo=None)  # noqa: DTZ001
    amz = aws4.to_amz_date(dt)

    assert amz == "20230102T030405Z"


def test_to_signer_date():
    dt = datetime(2023, 1, 2, 3, 4, 5, 12345, tzinfo=None)  # noqa: DTZ001
    amz = aws4.to_signer_date(dt)

    assert amz == "20230102"


@pytest.mark.parametrize(
    ("input_data", "expected"),
    [
        (b"input_string", "9f54d278014e50f71c789e6fba09c6cfb0945d9253eb8dc5f91ecf52e9996ab9"),
        ("input_string", "9f54d278014e50f71c789e6fba09c6cfb0945d9253eb8dc5f91ecf52e9996ab9"),
        (None, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ],
)
def test_sha256_hash_bytes_in(input_data, expected):
    out = aws4.sha256_hash(input_data)

    assert out == expected


@pytest.mark.parametrize(
    ("key", "data", "hexdigest", "expected"),
    [
        (
            b"key",
            b"data",
            False,
            b'P1\xfe=\x98\x9cm\x157\xa0\x13\xfans\x9d\xa24c\xfd\xae\xc3\xb7\x017\xd8(\xe3j\xce"\x1b\xd0',
        ),
        (b"key", b"data", True, "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0"),
        (
            bytearray("key", "utf-8"),
            b"data",
            False,
            b'P1\xfe=\x98\x9cm\x157\xa0\x13\xfans\x9d\xa24c\xfd\xae\xc3\xb7\x017\xd8(\xe3j\xce"\x1b\xd0',
        ),
        (bytearray("key", "utf-8"), b"data", True, "5031fe3d989c6d1537a013fa6e739da23463fdaec3b70137d828e36ace221bd0"),
    ],
)
def test_hmac_hash(key, data, hexdigest, expected):
    hmachash = aws4._hmac_hash(key, data, hexdigest=hexdigest)
    assert hmachash == expected


@pytest.mark.parametrize(
    ("headers", "canonical_headers", "signed_headers"),
    [
        ({}, "", ""),
        ({"Authorization": "ignored", "user-agent": "ignored"}, "", ""),
        ({"Authorization": "ignored", "user-agent": "ignored", "foo": "bar"}, "foo:bar", "foo"),
        ({"foo": "bar", "baz": "wut"}, "baz:wut\nfoo:bar", "baz;foo"),
        ({"FOO": "hello world", "baz": "wut"}, "baz:wut\nfoo:hello world", "baz;foo"),
        ({"foo": "hello    world", "BaZ": "wut"}, "baz:wut\nfoo:hello world", "baz;foo"),  # pragma: no-spell-check
    ],
)
def test_generate_canonical_headers(headers, canonical_headers, signed_headers):
    r = aws4._generate_canonical_headers(headers)

    assert r == (canonical_headers, signed_headers)


@pytest.mark.parametrize(
    ("query", "canonical_query"),
    [
        (b"foo=bar", "foo=bar"),
        (b"foo=bar&baz=faz", "baz=faz&foo=bar"),
        (b"foo=bar&foo=moo", "foo=bar&foo=moo"),
        (b"foo=moo&foo=bar", "foo=bar&foo=moo"),
    ],
)
def test_generate_canonical_query(query, canonical_query):
    r = aws4._generate_canonical_query_string(query)

    assert r == canonical_query


@pytest.mark.parametrize(
    ("secret_key", "date", "partition", "service_name", "expected"),
    [
        (
            "secret-key",
            "20230101",
            "partition",
            "service",
            b'\x9c.\xdb"v\x10\x17e\xbe\xa1\xd3\xa9\x0c\x07QC\xefS\x1f\x85|\x98xRoK\x86\x89\xdew\xfa\xec',
        ),
        (
            "secret-key2",
            "20230101",
            "partition",
            "service",
            b'\xba\x8a\xe12>\x90\x88\xae\xb0\x8f\xcd \xaa\x17?\xc9\x040\xc4\xe1CAa\xcc\xfa\x06\xd5\xfb"\x9dd\r',
        ),
        (
            "secret-key",
            "20230102",
            "partition",
            "service",
            b'\xd3\x7f3\x04|\xa6b\xac\xf6[\xd8\x88\xea\xe4"\x9e\xab\xbb\x99dh^{\x81\xd7\x0cH\x03\xd6v\x94\r',
        ),
        (
            "secret-key",
            "20230101",
            "partition2",
            "service",
            b'`\x1c\x8f\xd9"z\xfb\xb9\xc6\xbbgq\x1d_W\x9f\xca\xc0d\x05\xa1:L\xa8I\x81#\xd2\xb8\x0e n',
        ),
        (
            "secret-key",
            "20230101",
            "partition",
            "service2",
            b"uQ\xe5\xb92\xda\xac\x18\xcd\xf2jk&\x0cw\xea\xe0D\x8e>\x8c\x91N\xf8`\x05\xfc\xbd_\xe6\x82\xfb",
        ),
    ],
)
def test_generate_signing_key(secret_key, date, partition, service_name, expected):
    r = aws4.generate_signing_key(secret_key, date, partition, service_name)

    assert r == expected


def test_sign_request():
    s = aws4.sign_request(
        "s3",
        "PUT",
        mock.Mock(scheme="http", path="/signed", query=b""),
        "us-east-1",
        multidict.CIMultiDict(
            [
                ("host", "localhost:9004"),
                ("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                ("x-amz-date", "20230809T064301Z"),
            ],
        ),
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "AKIA0SYLV9QT8A6LKRD6",
        "r9RUbOHNG1tSugb4IVvmTKBbJ8D3XQnJqI_pEPYK",
        datetime(2023, 8, 9, 6, 43, 1, 67433, tzinfo=timezone.utc),
    )

    assert (
        s["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=AKIA0SYLV9QT8A6LKRD6/20230809/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=297e52e0243a99ef3fd140f1c8a605593be6b742bd92b19a23acc97e0a2053bb"
    )


def test_sign_request_url_string():
    s = aws4.sign_request(
        "s3",
        "PUT",
        "http://localhost:9004/signed",
        "us-east-1",
        multidict.CIMultiDict(
            [
                ("host", "localhost:9004"),
                ("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                ("x-amz-date", "20230809T064301Z"),
            ],
        ),
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "AKIA0SYLV9QT8A6LKRD6",
        "r9RUbOHNG1tSugb4IVvmTKBbJ8D3XQnJqI_pEPYK",
        datetime(2023, 8, 9, 6, 43, 1, 67433, tzinfo=timezone.utc),
    )

    assert (
        s["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=AKIA0SYLV9QT8A6LKRD6/20230809/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=297e52e0243a99ef3fd140f1c8a605593be6b742bd92b19a23acc97e0a2053bb"
    )


def test_sign_request_custom_algorithm():
    s = aws4.sign_request(
        "s3",
        "PUT",
        "http://localhost:9004/signed",
        "us-east-1",
        multidict.CIMultiDict(
            [
                ("host", "localhost:9004"),
                ("x-abc-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                ("x-abc-date", "20230809T064301Z"),
            ],
        ),
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "AKIA0SYLV9QT8A6LKRD6",
        "r9RUbOHNG1tSugb4IVvmTKBbJ8D3XQnJqI_pEPYK",
        datetime(2023, 8, 9, 6, 43, 1, 67433, tzinfo=timezone.utc),
        auth_schema=aws4.AuthSchema("ABC4-HMAC-SHA256", "x-abc"),
    )

    assert (
        s["Authorization"]
        == "ABC4-HMAC-SHA256 Credential=AKIA0SYLV9QT8A6LKRD6/20230809/us-east-1/s3/abc4_request, SignedHeaders=host;x-abc-content-sha256;x-abc-date, Signature=6d0f47bd38d4133835b8125998f6b2d27d98983062098244536028da76f600f2"
    )


def test_sign_request_injects_content_sha256():
    s = aws4.sign_request(
        "s3",
        "PUT",
        "http://localhost:9004/signed",
        "us-east-1",
        multidict.CIMultiDict(
            [
                ("host", "localhost:9004"),
                ("x-amz-date", "20230809T064301Z"),
            ],
        ),
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "AKIA0SYLV9QT8A6LKRD6",
        "r9RUbOHNG1tSugb4IVvmTKBbJ8D3XQnJqI_pEPYK",
        datetime(2023, 8, 9, 6, 43, 1, 67433, tzinfo=timezone.utc),
    )

    assert (
        s["Authorization"]
        == "AWS4-HMAC-SHA256 Credential=AKIA0SYLV9QT8A6LKRD6/20230809/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=cedf4734cb26a02378fbf4df4c049f86cef377bc52ddbcbca6b5063581fde193"
    )
