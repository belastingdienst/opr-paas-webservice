# opr-paas-webservice

## Goal

opr-paas-webservice is a Go-based API service that allows operators to encrypt and validate secrets for Paas
using RSA key pairs.

It supports:

* Encrypting secrets with a public key.
* Validating whether a Paas can be decrypted with provided keys.
* Health and readiness endpoints for operational monitoring.

This service is designed for secure key rotation and migration processes, ensuring secrets remain protected during transitions.

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