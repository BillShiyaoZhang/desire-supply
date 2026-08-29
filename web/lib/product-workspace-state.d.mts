import type { EditorResource, ResourceType } from "./app-contract.mjs";

type ScratchStorage = Pick<Storage, "setItem">;

export function persistEditorScratch(
  storage: ScratchStorage,
  resource: Pick<EditorResource, "resource_type" | "object_id" | "revision">,
  sections: Record<string, string>,
  savedAt?: Date,
): boolean;

export function isCreatePlaceholder(resourceType: ResourceType, objectId: string): boolean;
export function expectedEditorResponseObjectId(resourceType: ResourceType, objectId: string): string | undefined;
export function editorResponseBindingMatches(
  recordType: ResourceType,
  recordId: string,
  responseType: ResourceType,
  responseId: string,
): boolean;
export function formatDateTimeLocal(date: Date): string;
export function defaultDemandExpiry(now?: number): string;
export function dateTimeLocalToIso(value: string): string;
