export function parseLoopbackBaseUrl(value: string | undefined): URL;
export function createLoopbackProxyRequest(source: Request, baseUrl: string | undefined): Promise<Request>;
export function createAppProxyRequest(source: Request, baseUrl: string | undefined): Promise<Request>;
export function createAuthProxyRequest(source: Request, baseUrl: string | undefined): Promise<Request>;
export function createIamProxyRequest(source: Request, baseUrl: string | undefined): Promise<Request>;
export function proxyLocalRequest(source: Request, options?: {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}): Promise<Response>;
export function proxyAppRequest(source: Request, options?: {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}): Promise<Response>;
export function proxyAuthRequest(source: Request, options?: {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}): Promise<Response>;
export function proxyIamRequest(source: Request, options?: {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}): Promise<Response>;
