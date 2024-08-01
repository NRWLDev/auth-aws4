# Overview

`auth-aws4` aims to be a usecase agnostic implementation of AWS4 Sig v4, as
such it accepts the component pieces of a request rather than a full
opinionated request object like `httpx.Request`.

https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
