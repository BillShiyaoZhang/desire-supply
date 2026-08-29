import {
  DEMAND_EDITABLE_PATHS,
  PROFILE_EDITABLE_PATHS,
} from "./app-contract.mjs";
import { diffEditorVersionContent } from "./editor-version-diff.mjs";

function invalidMerge() {
  throw new TypeError("INVALID_EDITOR_CONFLICT_MERGE");
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function editablePaths(resourceType) {
  if (resourceType === "CREATOR_PROFILE") return PROFILE_EDITABLE_PATHS;
  if (resourceType === "DEMAND") return DEMAND_EDITABLE_PATHS;
  return invalidMerge();
}

function validateContent(content, allowedKeys, allowEmpty) {
  if (!isPlainObject(content)) invalidMerge();
  const keys = Object.keys(content);
  if (
    keys.some((key) => !allowedKeys.has(key))
    || (!allowEmpty || keys.length > 0) && keys.length !== allowedKeys.size
  ) {
    invalidMerge();
  }
  diffEditorVersionContent(content, content);
}

function sectionProjection(content, key) {
  return Object.hasOwn(content, key) ? { [key]: content[key] } : {};
}

function sectionEqual(left, right, key) {
  return diffEditorVersionContent(
    sectionProjection(left, key),
    sectionProjection(right, key),
  ).equal;
}

function cloneJson(value) {
  if (Array.isArray(value)) return value.map(cloneJson);
  if (isPlainObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, cloneJson(child)]),
    );
  }
  return value;
}

function freezeJson(value) {
  if (Array.isArray(value)) value.forEach(freezeJson);
  else if (isPlainObject(value)) Object.values(value).forEach(freezeJson);
  return value !== null && typeof value === "object" ? Object.freeze(value) : value;
}

function copySection(target, source, key) {
  if (Object.hasOwn(source, key)) target[key] = cloneJson(source[key]);
}

/**
 * Plan a bounded top-level three-way merge for the structured profile/demand editor.
 * Non-overlapping changes are automatic; only sections changed differently on both
 * sides accept an explicit SERVER or MINE choice.
 */
export function planEditorConflictMerge(resourceType, base, current, yours, choices = {}) {
  const paths = editablePaths(resourceType);
  const allowedKeys = new Set(paths.map((path) => path.slice(1)));
  validateContent(base, allowedKeys, true);
  validateContent(current, allowedKeys, false);
  validateContent(yours, allowedKeys, false);
  if (!isPlainObject(choices)) invalidMerge();

  const sections = [];
  const unresolvedPaths = [];
  const content = {};
  const consumedChoices = new Set();

  for (const path of paths) {
    const key = path.slice(1);
    const baseEqualsCurrent = sectionEqual(base, current, key);
    const baseEqualsYours = sectionEqual(base, yours, key);
    const currentEqualsYours = sectionEqual(current, yours, key);
    let state;
    let source;

    if (currentEqualsYours) {
      state = baseEqualsCurrent ? "UNCHANGED" : "SAME_CHANGE";
      source = "SERVER";
    } else if (baseEqualsCurrent) {
      state = "MINE_ONLY";
      source = "MINE";
    } else if (baseEqualsYours) {
      state = "SERVER_ONLY";
      source = "SERVER";
    } else {
      state = "COLLISION";
      source = Object.hasOwn(choices, path) ? choices[path] : null;
      if (source !== null && source !== "SERVER" && source !== "MINE") invalidMerge();
      if (source === null) unresolvedPaths.push(path);
      else consumedChoices.add(path);
    }

    if (source === "SERVER") copySection(content, current, key);
    else if (source === "MINE") copySection(content, yours, key);
    sections.push(Object.freeze({ path, state, choice: state === "COLLISION" ? source : null }));
  }

  if (Object.keys(choices).some((path) => !consumedChoices.has(path))) invalidMerge();
  const complete = unresolvedPaths.length === 0;
  return Object.freeze({
    complete,
    content: complete ? freezeJson(content) : null,
    sections: Object.freeze(sections),
    unresolvedPaths: Object.freeze(unresolvedPaths),
  });
}
