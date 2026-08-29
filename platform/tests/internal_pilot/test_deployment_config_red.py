from __future__ import annotations

from copy import deepcopy
from dataclasses import fields
import json
import unittest

from desire_platform.internal_pilot.deployment_config import (
    DEPLOYMENT_CONFIG_POINTER_ENV,
    InternalSandboxDeploymentConfigError,
    InternalSandboxDeploymentConfiguration,
    InternalSandboxOidcNetworkBinding,
    InternalSandboxOidcSettings,
    OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP,
    OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC,
    load_internal_sandbox_deployment_config_pointer,
    parse_internal_sandbox_deployment_config,
)


SYSTEM_ACTOR_ID = "10000000-0000-4000-8000-000000000001"


def valid_document():
    return {
        "schema_name": "desire-internal-sandbox-deployment-v1",
        "deployment_mode": "INTERNAL_SANDBOX",
        "external_participants_enabled": False,
        "internal_bff_origin": "http://api:8000",
        "runtime_config_path": "/run/desire/runtime-config.json",
        "secret_manifest_path": "/run/desire/secret-manifest.json",
        "secret_root": "/run/secrets",
        "postgres": {
            "host": "db",
            "port": 5432,
            "database": "desire",
            "transport_security": "TRUSTED_CONTAINER_NETWORK",
        },
        "oidc": {
            "issuer": "https://identity.example.test/tenant",
            "client_id": "desire-internal-sandbox",
            "client_secret_key_id": "oidc-client-v1",
            "redirect_uri": "https://pilot.example.test/v1/auth/oidc/callback",
            "allowed_signing_algorithms": ["RS256"],
            "metadata_ttl_seconds": 300,
            "request_timeout_seconds": 3,
            "maximum_response_bytes": 262144,
            "clock_skew_seconds": 30,
            "subject_digest_key_id": "oidc-subject-v1",
            "network_binding": {
                "mode": "SYSTEM_DNS_SYNTHETIC",
                "pinned_public_ipv4": None,
            },
        },
        "system_actor_id": SYSTEM_ACTOR_ID,
        "bind": {"host": "0.0.0.0", "port": 8000},
    }


def encode(document) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


class InternalSandboxDeploymentConfigTests(unittest.TestCase):
    def test_parses_closed_non_secret_deployment_bundle(self) -> None:
        config = parse_internal_sandbox_deployment_config(encode(valid_document()))

        self.assertIsInstance(config, InternalSandboxDeploymentConfiguration)
        self.assertEqual(config.deployment_mode, "INTERNAL_SANDBOX")
        self.assertFalse(config.external_participants_enabled)
        self.assertEqual(config.internal_bff_origin, "http://api:8000")
        self.assertEqual(config.postgres.host, "db")
        self.assertEqual(config.postgres.database, "desire")
        self.assertEqual(config.oidc.allowed_signing_algorithms, ("RS256",))
        self.assertEqual(
            config.oidc.network_binding.mode,
            OIDC_NETWORK_BINDING_SYSTEM_DNS_SYNTHETIC,
        )
        self.assertEqual(str(config.system_actor_id), SYSTEM_ACTOR_ID)
        self.assertEqual((config.bind.host, config.bind.port), ("0.0.0.0", 8000))
        self.assertNotIn("client_secret", {field.name for field in fields(config.oidc)})
        self.assertNotIn("never-render-this-material", repr(config))

    def test_rejects_open_modes_paths_endpoints_oidc_and_inline_secrets(self) -> None:
        invalid = []
        for path, value in (
            (("deployment_mode",), "CONTROLLED_PILOT"),
            (("external_participants_enabled",), True),
            (("internal_bff_origin",), "http://localhost:8000"),
            (("runtime_config_path",), "relative/runtime.json"),
            (("secret_root",), "/"),
            (("postgres", "host"), "localhost"),
            (("oidc", "issuer"), "http://identity.example.test"),
            (("oidc", "redirect_uri"), "https://pilot.example.test/callback"),
            (("oidc", "allowed_signing_algorithms"), ["none"]),
            (("system_actor_id",), "00000000-0000-0000-0000-000000000000"),
            (("bind", "host"), "api"),
            (("bind", "host"), "127.0.0.1"),
            (("bind", "port"), 8080),
            (("bind", "port"), True),
        ):
            document = valid_document()
            target = document
            for segment in path[:-1]:
                target = target[segment]
            target[path[-1]] = value
            invalid.append(document)

        inline = valid_document()
        inline["oidc"]["client_secret"] = "never-render-this-material"
        invalid.append(inline)
        dsn = valid_document()
        dsn["postgres"]["dsn"] = "postgres://admin:never-render-this-material@db/desire"
        invalid.append(dsn)

        for document in invalid:
            with self.subTest(document=document):
                with self.assertRaises(
                    InternalSandboxDeploymentConfigError
                ) as raised:
                    parse_internal_sandbox_deployment_config(encode(document))
                self.assertEqual(
                    raised.exception.code,
                    "INVALID_INTERNAL_SANDBOX_DEPLOYMENT_CONFIGURATION",
                )
                self.assertNotIn("never-render-this-material", str(raised.exception))

    def test_rejects_duplicate_keys_floats_unknown_fields_and_oversize(self) -> None:
        raw = encode(valid_document())
        duplicate = raw.replace(
            b'"deployment_mode":"INTERNAL_SANDBOX"',
            b'"deployment_mode":"INTERNAL_SANDBOX",'
            b'"deployment_mode":"INTERNAL_SANDBOX"',
        )
        unknown = deepcopy(valid_document())
        unknown["debug"] = False
        floating = deepcopy(valid_document())
        floating["oidc"]["request_timeout_seconds"] = 3.0

        for candidate in (duplicate, encode(unknown), encode(floating), b" " * 262145):
            with self.assertRaises(InternalSandboxDeploymentConfigError):
                parse_internal_sandbox_deployment_config(candidate)

    def test_real_binding_requires_one_canonical_global_public_ipv4(self) -> None:
        document = valid_document()
        document["oidc"]["issuer"] = "https://login.example.com/tenant"
        document["oidc"]["network_binding"] = {
            "mode": "PINNED_PUBLIC_IP",
            "pinned_public_ipv4": "8.8.8.8",
        }
        parsed = parse_internal_sandbox_deployment_config(encode(document))
        self.assertEqual(
            parsed.oidc.network_binding,
            InternalSandboxOidcNetworkBinding(
                mode=OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP,
                pinned_public_ipv4="8.8.8.8",
            ),
        )

        invalid_addresses = (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "2001:4860:4860::8888",
            "8.8.8.08",
        )
        for address in invalid_addresses:
            candidate = deepcopy(document)
            candidate["oidc"]["network_binding"]["pinned_public_ipv4"] = address
            with self.subTest(address=address), self.assertRaises(
                InternalSandboxDeploymentConfigError
            ):
                parse_internal_sandbox_deployment_config(encode(candidate))

    def test_synthetic_and_real_network_bindings_cannot_impersonate_each_other(self) -> None:
        real_over_system_dns = valid_document()
        real_over_system_dns["oidc"]["issuer"] = "https://login.example.com"
        synthetic_over_pinned = valid_document()
        synthetic_over_pinned["oidc"]["network_binding"] = {
            "mode": "PINNED_PUBLIC_IP",
            "pinned_public_ipv4": "8.8.8.8",
        }
        missing = valid_document()
        del missing["oidc"]["network_binding"]
        duplicate = encode(valid_document()).replace(
            b'"mode":"SYSTEM_DNS_SYNTHETIC"',
            b'"mode":"SYSTEM_DNS_SYNTHETIC",'
            b'"mode":"SYSTEM_DNS_SYNTHETIC"',
        )
        for candidate in (
            encode(real_over_system_dns),
            encode(synthetic_over_pinned),
            encode(missing),
            duplicate,
        ):
            with self.assertRaises(InternalSandboxDeploymentConfigError):
                parse_internal_sandbox_deployment_config(candidate)

    def test_direct_oidc_settings_constructor_closes_real_hostname_and_binding(self) -> None:
        facts = {
            "issuer": "https://login.example.com/tenant",
            "client_id": "client-v1",
            "client_secret_key_id": "client-secret-v1",
            "redirect_uri": "https://pilot.example.com/v1/auth/oidc/callback",
            "allowed_signing_algorithms": ("RS256",),
            "metadata_ttl_seconds": 300,
            "request_timeout_seconds": 3,
            "maximum_response_bytes": 262144,
            "clock_skew_seconds": 30,
            "subject_digest_key_id": "subject-v1",
            "network_binding": InternalSandboxOidcNetworkBinding(
                mode=OIDC_NETWORK_BINDING_PINNED_PUBLIC_IP,
                pinned_public_ipv4="8.8.8.8",
            ),
        }
        InternalSandboxOidcSettings(**facts)
        for issuer in (
            "https://127.0.0.1",
            "https://[2001:4860:4860::8888]",
            "https://login.example.test",
            "https://login.localhost",
            "https://login.local",
            "https://login.invalid",
            "https://login.example.123",
        ):
            with self.subTest(issuer=issuer), self.assertRaises(ValueError):
                InternalSandboxOidcSettings(**{**facts, "issuer": issuer})

    def test_loads_through_one_explicit_environment_pointer_only(self) -> None:
        paths = []

        config = load_internal_sandbox_deployment_config_pointer(
            environment={
                "PATH": "/usr/bin",
                DEPLOYMENT_CONFIG_POINTER_ENV: "/run/desire/deployment.json",
            },
            read_bytes=lambda path: paths.append(path) or encode(valid_document()),
        )

        self.assertEqual(config.bind.port, 8000)
        self.assertEqual(paths, ["/run/desire/deployment.json"])

        invalid_environments = (
            {},
            {DEPLOYMENT_CONFIG_POINTER_ENV: "relative.json"},
            {DEPLOYMENT_CONFIG_POINTER_ENV: "/run/secrets/deployment.json"},
            {
                DEPLOYMENT_CONFIG_POINTER_ENV: "/run/desire/deployment.json",
                "DESIRE_DATABASE_PASSWORD": "never-render-this-material",
            },
        )
        for environment in invalid_environments:
            with self.subTest(environment=environment):
                with self.assertRaises(InternalSandboxDeploymentConfigError) as raised:
                    load_internal_sandbox_deployment_config_pointer(
                        environment=environment,
                        read_bytes=lambda _path: encode(valid_document()),
                    )
                self.assertNotIn("never-render-this-material", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
