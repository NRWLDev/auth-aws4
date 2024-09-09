# Usecase agnostic implementation of AWS4 Sig v4
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![image](https://img.shields.io/pypi/v/auth-aws4.svg)](https://pypi.org/project/auth-aws4/)
[![image](https://img.shields.io/pypi/l/auth-aws4.svg)](https://pypi.org/project/auth-aws4/)
[![image](https://img.shields.io/pypi/pyversions/auth-aws4.svg)](https://pypi.org/project/auth-aws4/)
![style](https://github.com/NRWLDev/auth-aws4/actions/workflows/style.yml/badge.svg)
![tests](https://github.com/NRWLDev/auth-aws4/actions/workflows/tests.yml/badge.svg)
[![codecov](https://codecov.io/gh/NRWLDev/auth-aws4/branch/main/graph/badge.svg)](https://codecov.io/gh/NRWLDev/auth-aws4)

This implementation aims to be usecase agnostic. As such it accepts the
component pieces of a request rather than a full opinionated request object
like `httpx.Request`.

https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html

## Usage

### Validation

```python
from aws4 import generate_challenge, validate_challenge

payload = "<extract content from request>"

challenge = generate_challenge(
    method=request.method,
    url=request.url,
    headers=request.headers,
    content=payload.decode("utf-8"),
)

secret_access_key = <load secret key using the challenge.access_key_id>

validate_challenge(challenge, secret_key.secret_access_key)
```

### Signing

An example of an httpx AWS4 request signing. In this example the `Authorization` header is injected into `request.headers`

```python
from datetime import datetime, timezone

import aws4


service = "s3"
region = "us-east-1"
access_key_id = "my-access-key-id"
secret_access_key = "my-secret-access-key"

def http_aws4_auth(request: httpx.Request):
    dt = datetime.now(tz=timezone.utc)
    request.headers["x-amz-date"] = aws4.to_amz_date(dt)
    request.headers["host"] = request.url.netloc.decode("utf-8")

    body = request.content.decode("utf-8")
    if body:
        request.headers["Content-Length"] = str(len(body))

    aws4.sign_request(
        service,
        request.method,
        request.url,
        region,
        request.headers,
        body,
        access_key_id,
        secret_access_key,
        dt,
    )

with httpx.Client() as client:
    r = client.request(
        url="http://localhost",
        auth=auth,
    )
```

#### Builtin httpx client

Currently there is only a builtin client for httpx, if you think there is a
client implementation that would be useful to include, please raise an issue on
github.

```python
from datetime import datetime, timezone

import aws4
from aws4.key_pair import KeyPair
from aws4.client import HttpxAWS4Auth


auth = HttpxAWS4Auth(
    KeyPair(
        access_key_id="my-access-key-id",
        secret_access_key="my-secret-access-key",
    )
    "s3",
    "us-east-1",
)

with httpx.Client() as client:
    r = client.request(
        url="http://localhost",
        auth=auth,
    )
```

## Extra credit

Thanks to [@ozzzzz](https://www.github.com/ozzzzz) and
[@ivanmisic](https://www.github.com/ivanmisic) for work on the initial
httpx/fastapi implementations this was extracted from.
