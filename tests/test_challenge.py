from unittest import mock

import pytest
from freezegun import freeze_time

from aws4 import Challenge, _parse_authorization, generate_challenge, validate_challenge


def test_parse_authorization():
    authorization = "AWS4-HMAC-SHA256 Credential=AKIA0SYLV9QT8A6LKRD6/20230809/ksa/iam/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=297e52e0243a99ef3fd140f1c8a605593be6b742bd92b19a23acc97e0a2053bb"
    auth_type, credential, signed_headers, signature = _parse_authorization(authorization)
    assert auth_type == "AWS4-HMAC-SHA256"
    assert credential == "AKIA0SYLV9QT8A6LKRD6/20230809/ksa/iam/aws4_request"
    assert signed_headers == "host;x-amz-content-sha256;x-amz-date"
    assert signature == "297e52e0243a99ef3fd140f1c8a605593be6b742bd92b19a23acc97e0a2053bb"


@freeze_time("2023-08-09T01:02:03Z")
def test_generate_challenge():
    challenge = generate_challenge(
        method="PUT",
        url=mock.Mock(scheme="http", path="/my/path", query=b"foo=bar"),
        headers={
            "foo": "hello    world",
            "BaZ": "wut",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access-key/20230809/ksa/service/aws4_request, SignedHeaders=baz;foo, Signature=342103018e8cccefa7bd30ec2f41cbb9f9c5e5c9e9e9b434b773b95dc7dd5cbc",
            "x-amz-date": "20230809T010203Z",
            "x-amz-content-sha256": "651c1a60e695ffb695a3eb972fe3a661c97d7fb573b8d0bbfb439a7879fd952e",
        },
        content=b"somecontent",
    )

    assert challenge.access_key_id == "access-key"
    assert challenge.scope == "20230809/ksa/service/aws4_request"
    assert (
        challenge.string_to_sign
        == """AWS4-HMAC-SHA256
20230809T010203Z
20230809/ksa/service/aws4_request
651c1a60e695ffb695a3eb972fe3a661c97d7fb573b8d0bbfb439a7879fd952e"""
    )
    assert challenge.signature == "342103018e8cccefa7bd30ec2f41cbb9f9c5e5c9e9e9b434b773b95dc7dd5cbc"


@freeze_time("2023-08-09T01:02:03Z")
def test_generate_challenge_https():
    challenge = generate_challenge(
        method="PUT",
        url=mock.Mock(scheme="http", path="/my/path", query=b"foo=bar"),
        headers={
            "foo": "hello    world",
            "BaZ": "wut",
            "Authorization": "AWS4-HMAC-SHA256 Credential=access-key/20230809/ksa/service/aws4_request, SignedHeaders=baz;foo, Signature=f9a71a1bcce70ed6b1a27726f254fa400500821c81ab0e900f3df8c6278ca6a3",
            "x-amz-date": "20230809T010203Z",
            "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        },
        content=b"somecontent",
    )

    assert challenge.access_key_id == "access-key"
    assert challenge.scope == "20230809/ksa/service/aws4_request"
    assert (
        challenge.string_to_sign
        == """AWS4-HMAC-SHA256
20230809T010203Z
20230809/ksa/service/aws4_request
4728c2c554a0f3d622f903be4ab4f1f4586aaa446a853984e5a1a69d2b87b849"""
    )
    assert challenge.signature == "f9a71a1bcce70ed6b1a27726f254fa400500821c81ab0e900f3df8c6278ca6a3"


def test_validate_challenge():
    r = validate_challenge(
        Challenge(
            scope="20230809/ksa/service/aws4_request",
            string_to_sign="""AWS4-HMAC-SHA256
20230809T010203Z
20230809/ksa/service/aws4_request
651c1a60e695ffb695a3eb972fe3a661c97d7fb573b8d0bbfb439a7879fd952e""",
            signature="342103018e8cccefa7bd30ec2f41cbb9f9c5e5c9e9e9b434b773b95dc7dd5cbc",
        ),
        secret_access_key="secret-key",
    )

    assert r is None


@pytest.mark.parametrize(
    ("invalid_key"),
    [
        "scope",
        "string_to_sign",
        "signature",
        "secret_access_key",
    ],
)
def test_validate_challenge_invalid(invalid_key):
    kwargs = {
        "scope": "20230809/ksa/service/aws4_request",
        "string_to_sign": """AWS4-HMAC-SHA256
20230809T010203Z
20230809/ksa/service/aws4_request
651c1a60e695ffb695a3eb972fe3a661c97d7fb573b8d0bbfb439a7879fd952e""",
        "signature": "cf575a792cdda849ac5623947b863084f1e5a213eb46ab834a171f2fc72a7c09",
        "secret_access_key": "secret-key",
    }
    invalid_value = "invalid" if invalid_key != "scope" else "invalid/invalid/invalid/invalid"
    kwargs[invalid_key] = invalid_value

    secret_access_key = kwargs.pop("secret_access_key")
    challenge = Challenge(**kwargs)
    with pytest.raises(Exception, match="Invalid signature"):
        validate_challenge(challenge, secret_access_key)
