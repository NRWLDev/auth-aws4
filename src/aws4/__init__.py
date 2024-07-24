from __future__ import annotations

import datetime
import hashlib
import hmac
import logging
import re
import typing as t
import urllib
from collections import OrderedDict
from dataclasses import dataclass

from dateutil import parser

if t.TYPE_CHECKING:
    import multidict


logger = logging.getLogger(__name__)

_MULTI_SPACE_REGEX = re.compile(r"( +)")


class AWS4Exception(Exception):  # noqa: N818
    """Base class exception."""


class InvalidDateError(AWS4Exception):
    """Date drift detected."""


class MissingHeaderError(AWS4Exception):
    """Missing required header."""


class InvalidSignatureError(AWS4Exception):
    """Provided and generated signatures do not match."""


@dataclass
class Challenge:
    """Components of a challenge for validation."""

    scope: str
    string_to_sign: str
    signature: str
    access_key_id: str | None = None


def _parse_authorization(authorization: str) -> tuple[str, str, str, str]:
    """Extract credentials from AWS4 authorization header."""
    auth_type, _, credentials = authorization.partition(" ")
    parts = credentials.split(", ")
    data = {}
    for part in parts:
        k, _, v = part.partition("=")
        data[k.lower()] = v

    return auth_type, data["credential"], data["signedheaders"], data["signature"]


def _parse_key_date(headers: multidict.CIMultiDict) -> str:
    """Extract date header and check for drift/replay attacks."""
    key_date = headers.get("x-amz-date")
    if key_date is None:
        msg = "Missing supported date header"
        raise MissingHeaderError(msg)

    header = parser.parse(key_date)
    now = datetime.datetime.now(datetime.timezone.utc)
    delta = (now - header).total_seconds()
    if abs(delta) > 5:  # noqa: PLR2004
        msg = "Replay/drift detected in date."
        raise InvalidDateError(msg)

    return key_date


def sha256_hash(data: bytes | str | None) -> str:
    """Compute SHA-256 of data and return hash as hex encoded value."""
    data = data or b""
    data_ = data.encode() if isinstance(data, str) else data
    hasher = hashlib.sha256()
    hasher.update(data_)
    sha256sum = hasher.hexdigest()

    return sha256sum.decode() if isinstance(sha256sum, bytes) else sha256sum


def _hmac_hash(
    key: bytes | bytearray,
    data: bytes,
    *,
    hexdigest: bool = False,
) -> str | bytes:
    """Generate HMacSHA256 digest of given key and data."""
    hasher = hmac.new(key, data, hashlib.sha256)
    return hasher.hexdigest() if hexdigest else hasher.digest()


def _quote(
    resource: str,
    safe: str = "/",
    encoding: str | None = None,
    errors: str | None = None,
) -> str:
    return urllib.parse.quote(
        resource,
        safe=safe,
        encoding=encoding,
        errors=errors,
    ).replace("%7E", "~")


def _to_utc(value: datetime) -> datetime:
    """Convert to UTC time if value is not naive."""
    return value.astimezone(datetime.timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def to_amz_date(value: datetime) -> str:
    """Format datetime into AMZ date formatted string."""
    return _to_utc(value).strftime("%Y%m%dT%H%M%SZ")


def to_signer_date(value: datetime) -> str:
    """Format datetime into SignatureV4 date formatted string."""
    return _to_utc(value).strftime("%Y%m%d")


def _generate_canonical_headers(headers: multidict.CIMultiDict) -> tuple[str, str]:
    """Get canonical headers.

    CanonicalHeaders -
        The request headers, that will be signed, and their values, separated by newline characters.
        Header names must use lowercase characters, must appear in alphabetical order,
        and must be followed by a colon (:). For the values, trim any leading or trailing spaces,
        convert sequential spaces to a single space, and separate the values for a multi-value header using commas.
        You must include the host header (HTTP/1.1) or the :authority header (HTTP/2),
        and any x-amz-* headers in the signature.
        You can optionally include other standard headers in the signature, such as content-type.
    """
    canonical_headers = {}
    for key, values in headers.items():
        key_ = key.lower()
        if key_ not in ("authorization", "user-agent", "accept", "accept-encoding", "connection"):
            values_ = values if isinstance(values, (list, tuple)) else [values]
            canonical_headers[key_] = ",".join([_MULTI_SPACE_REGEX.sub(" ", value) for value in values_])

    canonical_headers = OrderedDict(sorted(canonical_headers.items()))
    signed_headers = ";".join(canonical_headers.keys())
    canonical_headers = "\n".join(
        [f"{key}:{value}" for key, value in canonical_headers.items()],
    )
    return canonical_headers, signed_headers


def _recreate_canonical_headers(headers: multidict.CIMultiDict, signed_headers: str) -> str:
    """Generate canonical headers from SignedHeaders.

    SignedHeaders -
        The list of headers that you included in CanonicalHeaders, separated by semicolons (;).
        This indicates which headers are part of the signing process.
        Header names must use lowercase characters and must appear in alphabetical order.
    """
    signed_headers_ = signed_headers.split(";")
    canonical_headers = {}
    for key, values in headers.items():
        key_ = key.lower()
        if key_ in signed_headers_:
            values_ = values if isinstance(values, (list, tuple)) else [values]
            canonical_headers[key_] = ",".join([_MULTI_SPACE_REGEX.sub(" ", value) for value in values_])

    canonical_headers = dict(sorted(canonical_headers.items()))
    return "\n".join(
        [f"{key}:{value}" for key, value in canonical_headers.items()],
    )


def _generate_canonical_query_string(query: bytes | str) -> str:
    """Get canonical query string.

    CanonicalQueryString -
        The URL-encoded query string parameters, separated by ampersands (&). Percent-encode reserved characters,
        including the space character. Encode names and values separately.
        If there are empty parameters, append the equals sign to the parameter name before encoding.
        After encoding, sort the parameters alphabetically by key name.
        If there is no query string, use an empty string ("").
    """
    query = query or ""
    query_: str = query.decode() if isinstance(query, bytes) else query
    return "&".join(
        [
            "=".join(pair)
            for pair in sorted(
                [params.split("=") for params in query_.split("&")],
            )
        ],
    )


def _generate_canonical_request_hash(
    method: str,
    url: str,
    headers: multidict.CIMultiDict,
    content_sha256: str,
) -> tuple[str, str]:
    r"""Get canonical request hash.

    https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html

    Create a canonical request by concatenating the following strings, separated by newline characters.
    This helps ensure that the signature that you calculate and the signature that the server calculates can match.

        HTTPMethod
        CanonicalUri
        CanonicalQueryString
        CanonicalHeaders
        SignedHeaders
        HashedPayload

    HTTPMethod -
        The HTTP method.

    CanonicalUri -
        The URI-encoded version of the absolute path component URL
        (everything between the host and the question mark character (?) that starts the query string parameters).
        If the absolute path is empty, use a forward slash character (/).

    CanonicalQueryString -
        The URL-encoded query string parameters, separated by ampersands (&). Percent-encode reserved characters,
        including the space character. Encode names and values separately.
        If there are empty parameters, append the equals sign to the parameter name before encoding.
        After encoding, sort the parameters alphabetically by key name.
        If there is no query string, use an empty string ("").

    CanonicalHeaders -
        The request headers, that will be signed, and their values, separated by newline characters.
        Header names must use lowercase characters, must appear in alphabetical order,
        and must be followed by a colon (:). For the values, trim any leading or trailing spaces,
        convert sequential spaces to a single space, and separate the values for a multi-value header using commas.
        You must include the host header (HTTP/1.1) or the :authority header (HTTP/2),
        and any x-amz-* headers in the signature.
        You can optionally include other standard headers in the signature, such as content-type.

    HashedPayload -
        A string created using the payload in the body of the HTTP request as input to a hash function.
        This string uses lowercase hexadecimal characters. If the payload is empty,
        use an empty string as the input to the hash function.

    CanonicalRequest =
      HTTPRequestMethod + '\n' +
      CanonicalURI + '\n' +
      CanonicalQueryString + '\n' +
      CanonicalHeaders + '\n\n' +
      SignedHeaders + '\n' +
    """
    canonical_headers, signed_headers = _generate_canonical_headers(headers)
    canonical_query_string = _generate_canonical_query_string(url.query)

    path = _quote(url.path or "/")

    canonical_request = (
        f"{method}\n"
        f"{path}\n"
        f"{canonical_query_string}\n"
        f"{canonical_headers}\n\n"
        f"{signed_headers}\n"
        f"{content_sha256}"
    )
    logger.debug(canonical_request)

    return sha256_hash(canonical_request), signed_headers


def _recreate_canonical_request_hash(
    method: str,
    url: str,
    headers: multidict.CIMultiDict,
    signed_headers: str,
    content_sha256: str,
) -> str:
    r"""Recreate canonical request hash.

    https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html

    Create a canonical request by concatenating the following strings, separated by newline characters.
    This helps ensure that the signature that you calculate and the signature that the server calculates can match.

        HTTPMethod
        CanonicalUri
        CanonicalQueryString
        CanonicalHeaders
        SignedHeaders
        HashedPayload

    HTTPMethod -
        The HTTP method.

    CanonicalUri -
        The URI-encoded version of the absolute path component URL
        (everything between the host and the question mark character (?) that starts the query string parameters).
        If the absolute path is empty, use a forward slash character (/).

    CanonicalQueryString -
        The URL-encoded query string parameters, separated by ampersands (&). Percent-encode reserved characters,
        including the space character. Encode names and values separately.
        If there are empty parameters, append the equals sign to the parameter name before encoding.
        After encoding, sort the parameters alphabetically by key name.
        If there is no query string, use an empty string ("").

    CanonicalHeaders -
        The request headers, that will be signed, and their values, separated by newline characters.
        Header names must use lowercase characters, must appear in alphabetical order,
        and must be followed by a colon (:). For the values, trim any leading or trailing spaces,
        convert sequential spaces to a single space, and separate the values for a multi-value header using commas.
        You must include the host header (HTTP/1.1) or the :authority header (HTTP/2),
        and any x-amz-* headers in the signature.
        You can optionally include other standard headers in the signature, such as content-type.

    SignedHeaders -
        The list of headers that you included in CanonicalHeaders, separated by semicolons (;).
        This indicates which headers are part of the signing process.
        Header names must use lowercase characters and must appear in alphabetical order.

    HashedPayload -
        A string created using the payload in the body of the HTTP request as input to a hash function.
        This string uses lowercase hexadecimal characters. If the payload is empty,
        use an empty string as the input to the hash function.

    CanonicalRequest =
      HTTPRequestMethod + '\n' +
      CanonicalURI + '\n' +
      CanonicalQueryString + '\n' +
      CanonicalHeaders + '\n\n' +
      SignedHeaders + '\n' +
    """
    canonical_headers = _recreate_canonical_headers(headers, signed_headers)
    canonical_query_string = _generate_canonical_query_string(url.query)

    path = _quote(url.path or "/")

    canonical_request = (
        f"{method}\n"
        f"{path}\n"
        f"{canonical_query_string}\n"
        f"{canonical_headers}\n\n"
        f"{signed_headers}\n"
        f"{content_sha256}"
    )

    return sha256_hash(canonical_request)


def generate_challenge(
    method: str,
    url: str,
    headers: multidict.CIMultiDict,
    content: bytes | None,
) -> Challenge:
    """Generate a challenge from request components."""
    auth_type, credential, signed_headers, signature = _parse_authorization(headers["Authorization"])

    content_sha256 = (
        sha256_hash(content)
        if headers.get("x-amz-content-sha256", "UNSIGNED-PAYLOAD") != "UNSIGNED-PAYLOAD"
        else "UNSIGNED-PAYLOAD"
    )

    access_key_id, scope = credential.split("/", maxsplit=1)
    date, region, service_name = scope.split("/")[:-1]
    key_date = _parse_key_date(headers)

    canonical_request_hash = _recreate_canonical_request_hash(
        method,
        url,
        headers,
        signed_headers,
        content_sha256,
    )

    string_to_sign = f"{auth_type}\n{key_date}\n{scope}\n{canonical_request_hash}"

    return Challenge(
        scope,
        string_to_sign,
        signature,
        access_key_id,
    )


def generate_signing_key(
    secret_access_key: str,
    date: str,
    region: str,
    service_name: str,
) -> str:
    """Generate a signing key.

    DateKey -
    HMAC-SHA256("AWS4" + <SecretAccessKey>, <yyyymmdd>)

    DateRegionKey -
    HMAC-SHA256(DateKey, <region>)

    DateRegionServiceKey -
    HMAC-SHA256(DateRegionKey, <service>)

    SigningKey -
    HMAC-SHA256(DateRegionServiceKey, "aws4_request")
    """
    date_key = _hmac_hash(
        ("AWS4" + secret_access_key).encode(),
        date.encode(),
    )
    date_region_key = _hmac_hash(date_key, region.encode())
    date_region_service_key = _hmac_hash(
        date_region_key,
        service_name.encode(),
    )
    return _hmac_hash(date_region_service_key, b"aws4_request")


def generate_signature(signing_key: str, string_to_sign: str) -> str:
    """Generate signature.

    Signature -
    Hex(HMAX-SHA256(SigningKey, StringToSign))
    """
    return _hmac_hash(signing_key, string_to_sign.encode(), hexdigest=True)


def validate_challenge(
    challenge: Challenge,
    secret_access_key: str,
) -> None:
    """Validate a provided challenge was signed by provided secret key.

    Args:
    ----
        challenge: Generated challenge for a request
        secret_access_key: Key pair private component

    Raises:
    ------
        InvalidSignatureError: Provided signature and generated signature do not match.
    """
    date, region, service_name = challenge.scope.split("/")[:-1]
    signing_key = generate_signing_key(
        secret_access_key,
        date,
        region,
        service_name,
    )

    signature_ = generate_signature(signing_key, challenge.string_to_sign)

    if signature_ != challenge.signature:
        msg = "Invalid signature"
        raise InvalidSignatureError(msg)


def sign_request(  # noqa: PLR0913
    service_name: str,
    method: str,
    url: str,
    region: str,
    headers: multidict.CIMultiDict,
    content: bytes | None,
    access_key_id: str,
    secret_access_key: str,
    date: datetime.datetime,
) -> multidict.CIMultiDict:
    """Sign request components with given access key pair.

    Args:
    ----
        service_name: Name of service being called
        method: Http request method
        url: Full url being called (querystring included)
        region: Service region
        headers: Http request headers
        content: Http request content
        access_key_id: Key pair public component
        secret_access_key: Key pair private component
        date: Request date time

    Returns:
    -------
        Original headers with Authorization injected.
    """
    url = urllib.parse.urlparse(url)
    logger.debug("url: %s", url)
    logger.debug("headers: %s", headers)

    content_sha256 = sha256_hash(content) if url.scheme == "http" else "UNSIGNED-PAYLOAD"
    content_header = "x-amz-content-sha256"
    if content_header not in headers:
        headers[content_header] = content_sha256

    scope = f"{to_signer_date(date)}/{region}/{service_name}/aws4_request"
    logger.debug("scope: %s", scope)

    canonical_request_hash, signed_headers = _generate_canonical_request_hash(
        method,
        url,
        headers,
        content_sha256,
    )
    string_to_sign = f"AWS4-HMAC-SHA256\n{to_amz_date(date)}\n{scope}\n{canonical_request_hash}"
    logger.debug("string_to_sign: %s", string_to_sign)

    signing_key = generate_signing_key(
        secret_access_key,
        to_signer_date(date),
        region,
        service_name,
    )
    logger.debug("signing_key: %s", signing_key)

    signature = generate_signature(signing_key, string_to_sign)
    logger.debug("generated_signature: %s", signature)

    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers