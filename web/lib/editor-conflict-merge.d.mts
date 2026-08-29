import type { ResourceType } from "./app-contract.mjs";

export type EditorConflictChoice = "SERVER" | "MINE";
export type EditorConflictSectionState =
  | "UNCHANGED"
  | "SAME_CHANGE"
  | "SERVER_ONLY"
  | "MINE_ONLY"
  | "COLLISION";

export type EditorConflictMergeSection = Readonly<{
  path: string;
  state: EditorConflictSectionState;
  choice: EditorConflictChoice | null;
}>;

export type EditorConflictMergePlan = Readonly<{
  complete: boolean;
  content: Readonly<Record<string, unknown>> | null;
  sections: readonly EditorConflictMergeSection[];
  unresolvedPaths: readonly string[];
}>;

export function planEditorConflictMerge(
  resourceType: ResourceType,
  base: Record<string, unknown>,
  current: Record<string, unknown>,
  yours: Record<string, unknown>,
  choices?: Readonly<Record<string, EditorConflictChoice>>,
): EditorConflictMergePlan;
