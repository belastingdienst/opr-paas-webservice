# opr-paas-webservice

## Goal

opr-paas-webservice is a Go-based API service that allows operators to encrypt and validate secrets for Paas
using RSA key pairs.

It supports:

* Encrypting secrets with a public key.
* Validating whether a Paas can be decrypted with provided keys.
* Health and readiness endpoints for operational monitoring.

This service is designed for secure key rotation and migration processes, ensuring secrets remain protected during transitions.

## Keys and deployment

The service reads its keys from files: the public key from `PAAS_PUBLIC_KEY_PATH`, and the private keys from `PAAS_PRIVATE_KEYS_PATH` (a file or a directory of key files, default `/secrets/paas/privateKeys`). It runs in one of two ways:

* **Encrypt-only (recommended for a web-facing service).** Mount only the public key. When the private key path does not exist, the service encrypts with the public key and the check endpoints (`/v1/checkpaas`, `/v2/checkpaas`) answer `503 Service Unavailable`. No key that can decrypt a Paas secret is held by the web-facing pod.
* **With private keys.** Mount the private keys too. The check endpoints then decrypt every secret of a Paas to verify it. The public key may be omitted when there is one private key, or one named `current`: its public key is then used to encrypt.

Responses when the keys cannot be used:

* The encrypt endpoints answer `500` when the keys cannot be loaded or encryption fails; `/v1/encrypt` returns its usual JSON with `valid: false` and an `error` message.
* The check endpoints answer `422` for a secret that does not decrypt, `503` in encrypt-only mode, and `500` when the keys cannot be loaded.
* `/readyz` answers `503` until the configured keys can encrypt; `/healthz` only reports that the process runs.

## Quickstart

One can run this webservice using the provided container image.

## Contributing

Please refer to our documentation in the [CONTRIBUTING.md](./CONTRIBUTING.md) file
and the Developer Guide section of the documentation site if you want to help us
improve the Paas Operator.

## License

Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.

See [LICENSE.md](./LICENSE.md) for details.