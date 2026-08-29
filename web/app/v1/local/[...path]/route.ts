import { proxyLocalRequest } from "../../../../lib/server-proxy.mjs";

function handle(request: Request): Promise<Response> {
  const baseUrl = process.env.DESIRE_LOOPBACK_BASE_URL
    ?? process.env.DESIRE_LOCAL_BACKEND
    ?? "http://127.0.0.1:8000";
  return proxyLocalRequest(request, { baseUrl });
}

export const GET = handle;
export const POST = handle;
export const DELETE = handle;
