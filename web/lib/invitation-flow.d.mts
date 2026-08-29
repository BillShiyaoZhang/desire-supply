export const PENDING_INVITATION_CONTEXT_KEY: "desire-pilot-invitation-context:v1";
export const PENDING_INVITATION_ACCEPTANCE_KEY: "desire-pilot-invitation-acceptance:v1";
export function captureAccessInvitationFragment(
  href: string,
  replaceLocation: (path: string) => void,
  expectedOrigin: string,
): string;
export function createInvitationStepUpBody(accessInvitationToken: string): {
  return_to: "/app";
  access_invitation_token: string;
};
export function createInvitationAuthorizationInit(
  accessInvitationToken: string,
  csrfToken: string | null,
): {
  method: "POST";
  credentials: "same-origin";
  headers: Record<string, string>;
  body: string;
};
export function createTokenlessStepUpBody(): { return_to: "/app"; reauthenticate: true };
export function parseIdentityAuthorizationUrl(value: unknown): string;
export function createJoinFlowCoordinator<T>(run: () => Promise<T> | T): {
  start(): Promise<T>;
};
