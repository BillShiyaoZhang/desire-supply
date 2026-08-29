const CAPABILITY_TOKEN = /^[A-Za-z0-9_-]{80,4096}$/;
const CSRF_TOKEN = /^[A-Za-z0-9_-]{32,512}$/;

export const PENDING_INVITATION_CONTEXT_KEY = "desire-pilot-invitation-context:v1";
export const PENDING_INVITATION_ACCEPTANCE_KEY = "desire-pilot-invitation-acceptance:v1";

function invalid() {
  throw new TypeError("ACCESS_INVITATION_FRAGMENT_INVALID");
}

export function captureAccessInvitationFragment(href, replaceLocation, expectedOrigin) {
  if (typeof href !== "string" || typeof replaceLocation !== "function" || typeof expectedOrigin !== "string") invalid();
  let url;
  try {
    url = new URL(href);
  } catch {
    invalid();
  }
  if (
    !new Set(["http:", "https:"]).has(url.protocol)
    || url.username
    || url.password
    || url.origin !== expectedOrigin
    || url.pathname !== "/join"
  ) invalid();

  // Scrub before parsing or returning the capability so a later render,
  // navigation, screenshot, or copied address cannot retain it.
  replaceLocation("/join");
  const prefix = "#access_invitation_token=";
  if (url.search || !url.hash.startsWith(prefix)) invalid();
  const token = url.hash.slice(prefix.length);
  if (!CAPABILITY_TOKEN.test(token)) invalid();
  return token;
}

export function createInvitationStepUpBody(accessInvitationToken) {
  if (typeof accessInvitationToken !== "string" || !CAPABILITY_TOKEN.test(accessInvitationToken)) invalid();
  return { return_to: "/app", access_invitation_token: accessInvitationToken };
}

export function createInvitationAuthorizationInit(accessInvitationToken, csrfToken) {
  const body = JSON.stringify(createInvitationStepUpBody(accessInvitationToken));
  if (csrfToken === null) {
    return {
      method: "POST",
      // Same-origin credentials mode is required so the browser accepts the
      // fresh HttpOnly OIDC binding cookie. The BFF strips any incoming
      // Session cookie before forwarding this anonymous invitation request.
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body,
    };
  }
  if (typeof csrfToken !== "string" || !CSRF_TOKEN.test(csrfToken)) {
    throw new TypeError("INVALID_INVITATION_AUTHORIZATION_REQUEST");
  }
  return {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json", "x-csrf-token": csrfToken },
    body,
  };
}

export function createTokenlessStepUpBody() {
  return { return_to: "/app", reauthenticate: true };
}

export function parseIdentityAuthorizationUrl(value) {
  if (typeof value !== "string") throw new TypeError("INVALID_AUTHORIZATION_RESPONSE");
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError("INVALID_AUTHORIZATION_RESPONSE");
  }
  if (
    url.origin !== "https://identity.example.test"
    || url.pathname !== "/authorize"
    || url.username
    || url.password
    || url.hash
  ) throw new TypeError("INVALID_AUTHORIZATION_RESPONSE");
  const expected = new Set([
    "client_id", "redirect_uri", "response_type", "scope", "state", "nonce",
    "code_challenge", "code_challenge_method",
  ]);
  const keys = [...url.searchParams.keys()];
  if (
    keys.length !== expected.size
    || new Set(keys).size !== keys.length
    || keys.some((key) => !expected.has(key))
    || url.searchParams.get("client_id") !== "desire-internal-sandbox"
    || url.searchParams.get("redirect_uri") !== "https://pilot.example.test/v1/auth/oidc/callback"
    || url.searchParams.get("response_type") !== "code"
    || url.searchParams.get("scope") !== "openid email"
    || url.searchParams.get("code_challenge_method") !== "S256"
    || !/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get("state") ?? "")
    || !/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get("nonce") ?? "")
    || !/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get("code_challenge") ?? "")
  ) throw new TypeError("INVALID_AUTHORIZATION_RESPONSE");
  return url.href;
}

export function createJoinFlowCoordinator(run) {
  if (typeof run !== "function") throw new TypeError("INVALID_JOIN_FLOW_TASK");
  let task = null;
  return Object.freeze({
    start() {
      task ??= Promise.resolve().then(run);
      return task;
    },
  });
}
