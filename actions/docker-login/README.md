# docker-login

This Github Action enables workflows to login to registries that use the
[`token-server`](../cmd/token-server) for authentication and authorization.


## Configuration

```
name: Example

on:
  push:
    branches: ['main']

permissions:
  contents: read
  id-token: write  # This is needed for OIDC federation.

jobs:
  example:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - uses: jetstack/jwt-registry-auth/actions/docker-login@main
        with:
          registry: registry.example.com
          username: gha # this is the name of the 'provider' in the token-server config

      - run: docker pull registry.example.com/library/alpine
```
