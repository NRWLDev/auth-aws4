# Usage

For usage examples I will be using `httpx`, but any other python request
library should be similar.

## Validation

```python
from aws4 import generate_challenge, validate_challenge

def fetch_secret_access_key(access_key_id) -> str:
    return "my-secret-access-key"


challenge = generate_challenge(
    method=request.method,
    url=request.url,
    headers=request.headers,
    content=request.content,
)

secret_access_key = fetch_access_key(challenge.access_key_id)

validate_challenge(challenge, secret_access_key)
```

## Signing

An example of an httpx AWS4 request signing. As part of the sign_request method
the `Authorization` header is injected into `request.headers`

```
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
        auth=http_aws4_auth,
    )
```

## Generate user keys

To generate user key pairs, `aws4.key_pair` provides some helpful utility functions.

```python
import aws4.key_pair

key_pair = aws4.key_pair.generate_key_pair()

ak = key_pair.access_key_id
sk = key_pair.secret_access_key
```
