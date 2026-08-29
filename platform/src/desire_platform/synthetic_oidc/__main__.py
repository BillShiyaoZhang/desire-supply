"""Run the container-network-only INTERNAL_SANDBOX synthetic OIDC fixture."""

from __future__ import annotations

import sys

from .http import SyntheticOidcHttpServer
from .provider import (
    SyntheticOidcConfigurationError,
    SyntheticOidcProvider,
    load_synthetic_oidc_configuration,
)


def main() -> int:
    configuration = None
    provider = None
    server = None
    try:
        configuration = load_synthetic_oidc_configuration()
        provider = SyntheticOidcProvider(client_secret=configuration.client_secret)
        server = SyntheticOidcHttpServer(
            (configuration.bind_host, configuration.bind_port), provider
        )
    except (SyntheticOidcConfigurationError, OSError, TypeError, ValueError):
        print("ERROR: synthetic OIDC startup failed closed", file=sys.stderr)
        if provider is not None:
            provider.close()
        if configuration is not None:
            configuration.close()
        return 1
    print(
        "INTERNAL_SANDBOX SYNTHETIC OIDC · G1 NO-GO · G2 NO-GO · registration closed",
        flush=True,
    )
    print("Listening on the private container endpoint 0.0.0.0:8081", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        provider.close()
        configuration.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
