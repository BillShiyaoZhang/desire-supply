import type { EditorChoiceField, EditorChoiceSource, EditorConfiguration, ResourceType } from "./app-contract.mjs";

export type StructuredIssue = { path: string; code: string };
export type FieldInputMeta = {
  type: "date" | "text" | "select";
  options: ReadonlyArray<{ value: string; label: string }>;
  multiline: boolean;
  readOnly: boolean;
  limits: readonly [number, number] | null;
  pattern: string | null;
};

export function sectionPaths(resourceType: ResourceType): readonly string[];
export function fieldLabel(key: string): string;
export function fieldInputMeta(key: string, canonicalPath: string, resourceType?: ResourceType | null): FieldInputMeta;
export function normalizeEditorChoicePath(canonicalPath: string): string;
export function resolveEditorChoice(configuration: EditorConfiguration | null | undefined, resourceType: ResourceType, canonicalPath: string): EditorChoiceField | null;
export function editorChoiceSourceLabel(source: EditorChoiceSource): string;
export function parseStructuredSection(resourceType: ResourceType, sectionPath: string, encoded: string): unknown;
export function serializeStructuredSection(value: unknown): string;
export function arrayItemTemplate(resourceType: ResourceType, canonicalPath: string, current: number | unknown[], configuration?: EditorConfiguration | null): unknown;
export function optionalValueTemplate(resourceType: ResourceType, canonicalPath: string): unknown;
export function hasOptionalValueTemplate(resourceType: ResourceType, canonicalPath: string): boolean;
export function structuredSectionIssues(resourceType: ResourceType, sectionPath: string, encoded: string, configuration?: EditorConfiguration | null): StructuredIssue[];
export function structuredContentIssues(resourceType: ResourceType, sections: Record<string, string>, configuration?: EditorConfiguration | null): StructuredIssue[];
export function issueMessage(code: string): string;
