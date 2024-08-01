# Custom Signing Algorithms

`auth-aws4` supports deviating from `AWS4-HMAX-SHA256` and `x-amz` headers if
you with to support a custom algorithm.

## Signing

```python
from datetime import datetime, timezone

import aws4


service = "s3"
region = "us-east-1"
access_key_id = "my-access-key-id"
secret_access_key = "my-secret-access-key"

CustomAuthSchema = aws4.AuthSchema("CUSTOM4-HMAC-SHA256", "x-custom")


def custom_auth(request: httpx.Request):
    dt = datetime.now(tz=timezone.utc)
    request.headers["x-amz-date"] = aws4.to_amz_date(dt)
    request.headers["host"] = request.url.netloc.decode("utf-8")

    body = request.content.decode("utf-8")
    if body:
        request.headers["Content-Length"] = str(len(body))

    aws4.sign_request(
        service,
        request.method,
        str(request.url),
        region,
        request.headers,
        body,
        access_key_id,
        secret_access_key,
        dt,
        CustomAuthSchema,
    )


with httpx.Client() as client:
    r = client.request(
        url="http://localhost",
        auth=custom_auth,
    )
```

## Validation

Server side the validation can support both `AWS4` and a custom algorithm, or
just a custom algorithm.

### AWS4 and Custom validation

```python
from aws4 import generate_challenge, validate_challenge

CustomAuthSchema = aws4.AuthSchema("CUSTOM4-HMAC-SHA256", "x-custom")


def fetch_secret_access_key(access_key_id) -> str:
    return "my-secret-access-key"


challenge = generate_challenge(
    method=request.method,
    url=request.url,
    headers=request.headers,
    content=request.content,
    supported_schemas=[aws4.AWSAuthSchema, CustomAuthSchema],
)

secret_access_key = fetch_access_key(challenge.access_key_id)

validate_challenge(
    challenge,
    secret_access_key,
    supported_schemas=[aws4.AWSAuthSchema, CustomAuthSchema],
)
```

### Without support for AWS4

```python
from aws4 import generate_challenge, validate_challenge

CustomAuthSchema = aws4.AuthSchema("CUSTOM4-HMAC-SHA256", "x-custom")


def fetch_secret_access_key(access_key_id) -> str:
    return "my-secret-access-key"


challenge = generate_challenge(
    method=request.method,
    url=request.url,
    headers=request.headers,
    content=request.content,
    supported_schemas=[CustomAuthSchema],
)

secret_access_key = fetch_access_key(challenge.access_key_id)

validate_challenge(
    challenge,
    secret_access_key,
    supported_schemas=[CustomAuthSchema],
)
```
