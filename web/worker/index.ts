/** Local vinext runtime. It declares no persistent or remote resource bindings. */
import handler from "vinext/server/app-router-entry";

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

const CSP_HEADER = "content-security-policy";
const CSP_REPORT_ONLY_HEADER = "content-security-policy-report-only";

function isHtmlDocumentRequest(request: Request): boolean {
  if (request.method !== "GET") return false;
  if (
    request.headers.get("rsc") === "1"
    || request.headers.has("next-router-state-tree")
    || request.headers.has("next-router-prefetch")
  ) return false;
  if (request.headers.get("sec-fetch-dest") === "document") return true;
  return (request.headers.get("accept") ?? "")
    .split(",")
    .some((value) => value.split(";", 1)[0]?.trim().toLowerCase() === "text/html");
}

function createCspNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function createContentSecurityPolicy(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'self' 'nonce-${nonce}'`,
    "script-src-attr 'none'",
    "style-src 'self'",
    "style-src-attr 'none'",
    "img-src 'self'",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "form-action 'self'",
    "manifest-src 'none'",
    "media-src 'none'",
    "worker-src 'none'",
  ].join("; ");
}

const worker = {
  async fetch(request: Request, env: unknown, ctx: ExecutionContext): Promise<Response> {
    if (!isHtmlDocumentRequest(request)) {
      return handler.fetch(request, env as Parameters<typeof handler.fetch>[1], ctx);
    }

    const nonce = createCspNonce();
    const policy = createContentSecurityPolicy(nonce);
    const requestHeaders = new Headers(request.headers);
    // Vinext reads the request CSP before rendering its inline RSC bootstrap.
    // Always replace untrusted client values so they cannot select the nonce.
    requestHeaders.delete(CSP_REPORT_ONLY_HEADER);
    requestHeaders.set(CSP_HEADER, policy);
    const response = await handler.fetch(
      new Request(request, { headers: requestHeaders }),
      env as Parameters<typeof handler.fetch>[1],
      ctx,
    );

    if (!/^text\/html\b/iu.test(response.headers.get("content-type") ?? "")) return response;
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set(CSP_HEADER, policy);
    responseHeaders.set("cache-control", "no-store");
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    });
  },
};

export default worker;
