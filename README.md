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

* **Encrypt-only (recommended for a web-facing service).** Set `PAAS_ENCRYPT_ONLY=true` and mount only the public key. The service encrypts with the public key and the check endpoints (`/v1/checkpaas`, `/v2/checkpaas`) answer `503 Service Unavailable`. No key that can decrypt a Paas secret is held by the web-facing pod. Private keys at `PAAS_PRIVATE_KEYS_PATH` are not used in this mode; the service logs a warning when they are mounted anyway.
* **With private keys** (the default). Mount the private keys too. When the private key path does not exist, requests fail and `/readyz` answers `503`: a missing path does not switch to encrypt-only by itself, so a typo in `PAAS_PRIVATE_KEYS_PATH` cannot disable the checks unnoticed. The check endpoints then decrypt every secret of a Paas to verify it. The public key may be omitted when there is one private key, or one named `current`: its public key is then used to encrypt.

Responses when the keys cannot be used:

* The encrypt endpoints answer `500` when the keys cannot be loaded or encryption fails, with their usual JSON: `valid: false` and an `error` message.
* The check endpoints answer `422` for a secret that does not decrypt, `503` in encrypt-only mode, and `500` when the keys cannot be loaded.
* `/readyz` answers `503` while the configured keys cannot be loaded, and in encrypt-only mode also while they cannot encrypt. With private keys, keys that can decrypt but not encrypt (two private keys and no public key, as during a rotation) keep the service ready: the check endpoints still work and only the encrypt endpoints answer `500`. `/healthz` only reports that the process runs.

## TLS

By default the service serves plain HTTP, and TLS ends in front of it, for example at an OpenShift route with `edge` termination. The secrets that clients send then cross the cluster network unencrypted after the route.

To serve TLS from the service itself, set `PAAS_TLS_CERT_FILE` and `PAAS_TLS_KEY_FILE` to a PEM certificate and its private key, for example the `tls.crt` and `tls.key` of a mounted `kubernetes.io/tls` Secret. Set both or neither; the service does not start with only one, or when the files cannot be loaded. A changed certificate, such as one renewed by cert-manager, is used for new connections without a restart; when the changed files cannot be loaded, the previous certificate is kept and an error is logged.

Use a `passthrough` route to keep TLS from the client up to the service, or a `reencrypt` route to keep the hop after the route encrypted. Probes then need `scheme: HTTPS`.

The service keeps Go's TLS defaults. Clients that support it, such as current browsers, curl with OpenSSL 3.5 or later, and Go 1.24 or later, negotiate the hybrid post-quantum key exchange `X25519MLKEM768`, so a recorded session cannot be decrypted later with a quantum computer.

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