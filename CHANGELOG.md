# Changelog

## v0.1.10 - 2025-05-05

### Documentation

- Add documentation url for pypi. [[7fd4eb8](https://github.com/NRWLDev/auth-aws4/commit/7fd4eb8d9db7d7829d0c994f2826e92384f8e6d8)]

## v0.1.9 - 2025-05-05

### Bug fixes

- Ensure urls render in pypi. [[c0d62bf](https://github.com/NRWLDev/auth-aws4/commit/c0d62bf5ba5b04bde1eb7c5fcb8c75cd7845be34)]

## v0.1.8 - 2024-09-09

### Miscellaneous

- Migrate from poetry to uv for dependency and build management [[5246097](https://github.com/NRWLDev/auth-aws4/commit/5246097c593b376276870cfccf86aa029928e53b)]
- Update changelog-gen and related configuration. [[f8f51b9](https://github.com/NRWLDev/auth-aws4/commit/f8f51b9fa80530a2951cdad74b2f1b7d93057b10)]

## v0.1.7 - 2024-08-30

### Features and Improvements

- Implement httpx client using httpx.Auth instead of a callable. [[c5be7fc](https://github.com/NRWLDev/auth-aws4/commit/c5be7fcf32c33eea40c60e6992421df37149be85)]

## v0.1.6 - 2024-08-03

### Features and Improvements

- Add httpx auth implementation with httpx.Request protocol for type hinting. [[54aba90](https://github.com/NRWLDev/auth-aws4/commit/54aba90fd2f88a36f93516891b2956f08866bddf)]

### Miscellaneous

- Fix type hints for URL protocol. [[3e1e5ec](https://github.com/NRWLDev/auth-aws4/commit/3e1e5ec8716878c2aab35602b951c8ff600ba8ec)]

## v0.1.5 - 2024-08-03

### Features and Improvements

- Add keypair generation utils [[#1](https://github.com/NRWLDev/auth-aws4/issues/1)] [[5da7743](https://github.com/NRWLDev/auth-aws4/commit/5da774396a9017e7560e7f177abaea5cd3164399)]

## v0.1.4 - 2024-08-01

### Bug fixes

- Fix datetime type hints. [[45ef312](https://github.com/NRWLDev/auth-aws4/commit/45ef312ec512b3535d194571aeb607f44d9ce726)]
- Improve typing to support passing URL objects directly. [[e14ad65](https://github.com/NRWLDev/auth-aws4/commit/e14ad659494bba1799ee77465c692ccecfd98e5c)]

### Miscellaneous

- Add initial documentation. [[1b31d4a](https://github.com/NRWLDev/auth-aws4/commit/1b31d4a3d33ae60571e355c18a30590fb1470d21)]
- Add tests for URL and str based urls. [[1aeeaa5](https://github.com/NRWLDev/auth-aws4/commit/1aeeaa5d5c25a6ba130675cb62bad5e25f152b5e)]

## v0.1.3 - 2024-07-30

### Bug fixes

- Add dateutil as a dependency [[6b7bb14](https://github.com/NRWLDev/auth-aws4/commit/6b7bb147b759bb4225948a6cb5f2d29800e21efa)]

### Miscellaneous

- Add tests for custom algorithm support [[d6888e5](https://github.com/NRWLDev/auth-aws4/commit/d6888e5aeaeb8ec1643cb0f87292ca4c58361384)]

## v0.1.2 - 2024-07-24

### Features and Improvements

- Add support for custom header algorithms [[00e905a](https://github.com/NRWLDev/auth-aws4/commit/00e905ac771ecfbd8d790575009b62a86b5bc424)]

## v0.1.1 - 2024-07-24

### Miscellaneous

- Add py.typed file [[9f2c82f](https://github.com/NRWLDev/auth-aws4/commit/9f2c82f86e654d7a83c2b642a81d0e4a6f8ab902)]

## v0.1.0 - 2024-07-24

### Features and Improvements

- Initial implementation of AWS4 request signing. [[d8efa43](https://github.com/NRWLDev/auth-aws4/commit/d8efa433ebff5764277a21abd6cdf09e16882c81)]
