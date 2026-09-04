export type WorkspaceView = "tasks" | "profiles" | "demands" | "review" | "funding" | "matching" | "matching-review" | "trust" | "appeal" | "organization" | "accounts" | "timeline" | "security";
export type WorkspaceNavigationItem = { id: WorkspaceView; label: string; description: string; group: string; icon: string };
export function buildWorkspaceNavigation(capabilities: Record<string, boolean>): WorkspaceNavigationItem[];
export function resolveWorkspaceView(requested: WorkspaceView, navigation: WorkspaceNavigationItem[], pendingOwner: string | null): WorkspaceView;
export function workspaceViewForTarget(elementId: string): WorkspaceView;
