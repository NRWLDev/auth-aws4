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
class AuthSchema:
    """Configuration for a supported schema."""

    algorithm: str
    header_prefix: str

    @property
    def schema(self: t.Self) -> str:
        """Extract the algorithm prefix."""
        return self.algorithm.split("-")[0]


AWSAuthSchema = AuthSchema("AWS4-HMAC-SHA256", "x-amz")


class URL(t.Protocol):
    """Abstract definition of a URL object suitable for AWS4 signing."""

    @property
    def netloc(self) -> str | bytes:
        """Network location where the request is made to."""

    @property
    def scheme(self) -> str:
        """Specified URL scheme for the request."""

    @property
    def query(self) -> str | bytes:
        """URL query component.

        The query component, that contains non-hierarchical data, that along with data
        in path component, identifies a resource in the scope of URI's scheme and
        network location.
        """

    @property
    def path(self) -> str:
        """The hierarchical path, such as the path to a file to download."""


@dataclass
class Challenge:
    """Components of a challenge for validation."""

    algorithm: str
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


def _parse_key_date(headers: t.Mapping[str, str], prefix: str = "x-amz") -> str:
    """Extract date header and check for drift/replay attacks."""
    key_date = headers.get(f"{prefix}-date")
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


def _to_utc(value: datetime.datetime) -> datetime.datetime:
    """Convert to UTC time if value is not naive."""
    return value.astimezone(datetime.timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def to_amz_date(value: datetime.datetime) -> str:
    """Format datetime into AMZ date formatted string."""
    return _to_utc(value).strftime("%Y%m%dT%H%M%SZ")


def to_signer_date(value: datetime.datetime) -> str:
    """Format datetime into SignatureV4 date formatted string."""
    return _to_utc(value).strftime("%Y%m%d")


def _generate_canonical_headers(headers: t.Mapping[str, str]) -> tuple[str, str]:
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


def _recreate_canonical_headers(headers: t.Mapping[str, str], signed_headers: str) -> str:
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
    url: URL,
    headers: t.Mapping[str, str],
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
    url: URL,
    headers: t.Mapping[str, str],
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
    url: str | URL,
    headers: t.Mapping[str, str],
    content: str | bytes | None,
    supported_schemas: list = [AWSAuthSchema],  # noqa: B006
) -> Challenge:
    """Generate a challenge from request components.

    Args:
    ----
        method: Http request method
        url: Full url being called (querystring included)
        headers: Http request headers, case insensitive multidict
        content: Http request content
        supported_schemas: List of supported algorithm/header prefix settings.
    """
    if isinstance(url, str):
        url = urllib.parse.urlparse(url)
    _schemas = {as_.algorithm: as_ for as_ in supported_schemas}
    algorithm, credential, signed_headers, signature = _parse_authorization(headers["Authorization"])
    auth_schema = _schemas[algorithm]

    content_sha256 = (
        sha256_hash(content)
        if headers.get(f"{auth_schema.header_prefix}-content-sha256", "UNSIGNED-PAYLOAD") != "UNSIGNED-PAYLOAD"
        else "UNSIGNED-PAYLOAD"
    )

    access_key_id, scope = credential.split("/", maxsplit=1)
    date, region, service_name = scope.split("/")[:-1]
    key_date = _parse_key_date(headers, auth_schema.header_prefix)

    canonical_request_hash = _recreate_canonical_request_hash(
        method,
        url,
        headers,
        signed_headers,
        content_sha256,
    )

    string_to_sign = f"{auth_schema.algorithm}\n{key_date}\n{scope}\n{canonical_request_hash}"

    return Challenge(
        algorithm,
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
    schema: str = "AWS4",
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
        (schema + secret_access_key).encode(),
        date.encode(),
    )
    date_region_key = _hmac_hash(date_key, region.encode())
    date_region_service_key = _hmac_hash(
        date_region_key,
        service_name.encode(),
    )
    return _hmac_hash(date_region_service_key, f"{schema.lower()}_request".encode())


def generate_signature(signing_key: str, string_to_sign: str) -> str:
    """Generate signature.

    Signature -
    Hex(HMAX-SHA256(SigningKey, StringToSign))
    """
    return _hmac_hash(signing_key, string_to_sign.encode(), hexdigest=True)


def validate_challenge(
    challenge: Challenge,
    secret_access_key: str,
    supported_schemas: list = [AWSAuthSchema],  # noqa: B006
) -> None:
    """Validate a provided challenge was signed by provided secret key.

    Args:
    ----
        challenge: Generated challenge for a request
        secret_access_key: Key pair private component
        supported_schemas: List of supported algorithm/header prefix settings.

    Raises:
    ------
        InvalidSignatureError: Provided signature and generated signature do not match.
    """
    _schemas = {as_.algorithm: as_ for as_ in supported_schemas}
    auth_schema = _schemas[challenge.algorithm]
    date, region, service_name = challenge.scope.split("/")[:-1]
    signing_key = generate_signing_key(
        secret_access_key,
        date,
        region,
        service_name,
        auth_schema.schema,
    )

    signature_ = generate_signature(signing_key, challenge.string_to_sign)

    if signature_ != challenge.signature:
        logger.debug("generated: %s", signature_)
        logger.debug("challenge: %s", challenge.signature)
        msg = "Invalid signature"
        raise InvalidSignatureError(msg)


def sign_request(  # noqa: PLR0913
    service_name: str,
    method: str,
    url: str | URL,
    region: str,
    headers: t.Mapping[str, str],
    content: str | bytes | None,
    access_key_id: str,
    secret_access_key: str,
    date: datetime.datetime,
    auth_schema: AuthSchema = AWSAuthSchema,
) -> t.Mapping[str, str]:
    """Sign request components with given access key pair.

    Args:
    ----
        service_name: Name of service being called
        method: Http request method
        url: Full url being called (querystring included)
        region: Service region
        headers: Http request headers, case insensitive multidict
        content: Http request content
        access_key_id: Key pair public component
        secret_access_key: Key pair private component
        date: Request date time
        auth_schema: Optional custom schema definition

    Returns:
    -------
        Original headers with Authorization injected.
    """
    if isinstance(url, str):
        url = urllib.parse.urlparse(url)
    logger.debug("url: %s", url)
    logger.debug("headers: %s", headers)

    content_sha256 = sha256_hash(content) if url.scheme == "http" else "UNSIGNED-PAYLOAD"
    content_header = f"{auth_schema.header_prefix}-content-sha256"
    if content_header not in headers:
        headers[content_header] = content_sha256

    scope = f"{to_signer_date(date)}/{region}/{service_name}/{auth_schema.schema.lower()}_request"
    logger.debug("scope: %s", scope)

    canonical_request_hash, signed_headers = _generate_canonical_request_hash(
        method,
        url,
        headers,
        content_sha256,
    )
    string_to_sign = f"{auth_schema.algorithm}\n{to_amz_date(date)}\n{scope}\n{canonical_request_hash}"
    logger.debug("string_to_sign: %s", string_to_sign)

    signing_key = generate_signing_key(
        secret_access_key,
        to_signer_date(date),
        region,
        service_name,
        auth_schema.schema,
    )
    logger.debug("signing_key: %s", signing_key)

    signature = generate_signature(signing_key, string_to_sign)
    logger.debug("generated_signature: %s", signature)

    headers["Authorization"] = (
        f"{auth_schema.algorithm} Credential={access_key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers
