import { headers } from "next/headers";
import { JoinClient } from "./join-client";

const CSP_NONCE = /^'nonce-([A-Za-z0-9_-]{43})'$/u;

function joinScriptNonce(policy: string | null): string | undefined {
  // RSC navigations are not HTML document responses and intentionally carry
  // no document CSP. The first-paint document path is nonce-bound below;
  // JoinClient retains the synchronous in-memory fallback for RSC navigation.
  if (policy === null) return undefined;
  const directives = policy
    .split(";")
    .map((value) => value.trim())
    .filter((value) => value.startsWith("script-src "));
  if (directives.length !== 1) throw new Error("JOIN_CSP_NONCE_UNAVAILABLE");
  const nonces = directives[0]
    .slice("script-src ".length)
    .split(/\s+/u)
    .map((value) => CSP_NONCE.exec(value))
    .filter((value): value is RegExpExecArray => value !== null);
  if (nonces.length !== 1) throw new Error("JOIN_CSP_NONCE_UNAVAILABLE");
  return nonces[0][1];
}

const JOIN_BOOTSTRAP = String.raw`(() => {
  "use strict";
  const property = "__DESIRE_JOIN_BOOTSTRAP__";
  let capability = null;
  let error = null;
  try {
    const source = new URL(window.location.href);
    const prefix = "#access_invitation_token=";
    window.history.replaceState(null, "", "/join");
    if (
      source.origin !== window.location.origin
      || source.pathname !== "/join"
      || source.search
      || !source.hash.startsWith(prefix)
    ) throw new TypeError("ACCESS_INVITATION_FRAGMENT_INVALID");
    const candidate = source.hash.slice(prefix.length);
    if (!/^[A-Za-z0-9_-]{80,4096}$/.test(candidate)) {
      throw new TypeError("ACCESS_INVITATION_FRAGMENT_INVALID");
    }
    capability = candidate;
  } catch {
    error = "ACCESS_INVITATION_FRAGMENT_INVALID";
    if (window.location.pathname === "/join") {
      window.history.replaceState(null, "", "/join");
    }
  }
  Object.defineProperty(window, property, {
    configurable: true,
    value: { capability, error },
  });
})();`;

export default async function JoinPage() {
  const nonce = joinScriptNonce(
    (await headers()).get("content-security-policy"),
  );
  return (
    <>
      <script
        id="desire-join-fragment-scrub"
        nonce={nonce}
        suppressHydrationWarning
        dangerouslySetInnerHTML={{ __html: JOIN_BOOTSTRAP }}
      />
      <JoinClient />
    </>
  );
}
