import { proxyAuthRequest } from "../../../../../lib/server-proxy.mjs";

export function DELETE(request: Request): Promise<Response> {
  const baseUrl = process.env.DESIRE_LOOPBACK_BASE_URL
    ?? process.env.DESIRE_LOCAL_BACKEND
    ?? "http://127.0.0.1:8000";
  return proxyAuthRequest(request, { baseUrl });
}
