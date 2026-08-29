export type EditorDiffValue =
  | Readonly<{ value_type: "NULL" }>
  | Readonly<{ value_type: "STRING"; value: string }>
  | Readonly<{ value_type: "NUMBER"; value: number }>
  | Readonly<{ value_type: "BOOLEAN"; value: boolean }>
  | Readonly<{ value_type: "EMPTY_ARRAY" }>
  | Readonly<{ value_type: "EMPTY_OBJECT" }>
  | Readonly<{ value_type: "ARRAY"; size: number }>
  | Readonly<{ value_type: "OBJECT"; size: number }>
  | Readonly<{ value_type: "ITEM_ORDER"; value: readonly string[] }>;

export type EditorDiffChange = Readonly<{
  type: "ADDED" | "REMOVED" | "CHANGED";
  path: string;
  before: EditorDiffValue | null;
  after: EditorDiffValue | null;
}>;

export type EditorVersionDiff = Readonly<{
  equal: boolean;
  changes: readonly EditorDiffChange[];
}>;

export function diffEditorVersionContent(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
): EditorVersionDiff;
