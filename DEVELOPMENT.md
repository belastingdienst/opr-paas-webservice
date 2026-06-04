# Local development guide

## Creating a local development environment

TL;DR is:
- to get started, just run `make setup-e2e` (for podman you can run `CONTAINER_TOOL=podman make setup-e2e`.
- in one shell, open a port-forward: `kubectl port-forward -n paas-system service/opr-paas-webservice 8080:80`
- in another shell:
  - create a payload, run:
    ```bash
    ssh-keygen -a 256 -t ed25519 -N "" -f example-key
    export PAYLOAD=$(cat example-key | python3 ./scripts/ssh2json )
    ```
  - use curl to request the api (e.a. /v1/encrypt):
    `curl -X POST http://localhost:8080/v1/encrypt -H 'Content-Type: application/json' -d "$PAYLOAD"`
- If you have changed code and refresh the deployment:
  ```bash
  make image-build kind-image-load redeploy-webservice
  ```
  After that, you need to restart the port forwarding (as it was linked to the pod you just killed).
