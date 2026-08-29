const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 50_000;

const STABLE_REPEATER_IDENTITIES = new Map([
  ["/scope/deliverables", "item_id"],
  ["/acceptance/criteria", "criterion_id"],
  ["/milestone_plan/items", "item_id"],
]);

const CHANGE_ORDER = Object.freeze({ REMOVED: 0, CHANGED: 1, ADDED: 2 });

function invalidContent() {
  throw new TypeError("INVALID_EDITOR_VERSION_CONTENT");
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateJsonValue(value, seen, state, depth) {
  state.nodes += 1;
  if (state.nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) invalidContent();

  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) invalidContent();
    return;
  }
  if (typeof value !== "object" || seen.has(value)) invalidContent();
  seen.add(value);

  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")
      || keys.length !== value.length + 1
      || keys.at(-1) !== "length") invalidContent();
    for (let index = 0; index < value.length; index += 1) {
      if (keys[index] !== String(index)) invalidContent();
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, "value") || !descriptor.enumerable) invalidContent();
      validateJsonValue(descriptor.value, seen, state, depth + 1);
    }
  } else {
    if (!isPlainObject(value)) invalidContent();
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") invalidContent();
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, "value") || !descriptor.enumerable) invalidContent();
      validateJsonValue(descriptor.value, seen, state, depth + 1);
    }
  }

  seen.delete(value);
}

function validateContent(content) {
  if (!isPlainObject(content)) invalidContent();
  validateJsonValue(content, new WeakSet(), { nodes: 0 }, 0);
}

function pointerSegment(value) {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function childPath(path, segment) {
  return `${path}/${pointerSegment(segment)}`;
}

function scalarValue(value) {
  if (value === null) return Object.freeze({ value_type: "NULL" });
  if (typeof value === "string") return Object.freeze({ value_type: "STRING", value });
  if (typeof value === "number") return Object.freeze({ value_type: "NUMBER", value });
  if (typeof value === "boolean") return Object.freeze({ value_type: "BOOLEAN", value });
  if (Array.isArray(value)) {
    if (value.length === 0) return Object.freeze({ value_type: "EMPTY_ARRAY" });
    return Object.freeze({ value_type: "ARRAY", size: value.length });
  }
  const size = Object.keys(value).length;
  if (size === 0) return Object.freeze({ value_type: "EMPTY_OBJECT" });
  return Object.freeze({ value_type: "OBJECT", size });
}

function orderValue(ids) {
  return Object.freeze({ value_type: "ITEM_ORDER", value: Object.freeze([...ids]) });
}

function change(changes, type, path, before, after) {
  changes.push(Object.freeze({
    type,
    path: path || "/",
    before: before === undefined ? null : scalarValue(before),
    after: after === undefined ? null : scalarValue(after),
  }));
}

function stableItems(value, identityKey) {
  const items = new Map();
  for (const item of value) {
    if (!isPlainObject(item) || typeof item[identityKey] !== "string" || !item[identityKey]) return null;
    const identity = item[identityKey];
    if (items.has(identity)) return null;
    items.set(identity, item);
  }
  return items;
}

function stableItemPath(path, identityKey, identity) {
  return childPath(path, `@${identityKey}=${identity}`);
}

function walkOneSided(value, path, type, changes) {
  if (Array.isArray(value)) {
    if (value.length === 0) {
      change(changes, type, path, type === "REMOVED" ? value : undefined, type === "ADDED" ? value : undefined);
      return;
    }
    const identityKey = STABLE_REPEATER_IDENTITIES.get(path);
    const stable = identityKey ? stableItems(value, identityKey) : null;
    if (stable) {
      for (const identity of [...stable.keys()].sort()) {
        walkOneSided(stable.get(identity), stableItemPath(path, identityKey, identity), type, changes);
      }
      return;
    }
    value.forEach((item, index) => walkOneSided(item, childPath(path, String(index)), type, changes));
    return;
  }
  if (isPlainObject(value)) {
    const keys = Object.keys(value).sort();
    if (keys.length === 0) {
      change(changes, type, path, type === "REMOVED" ? value : undefined, type === "ADDED" ? value : undefined);
      return;
    }
    for (const key of keys) walkOneSided(value[key], childPath(path, key), type, changes);
    return;
  }
  change(changes, type, path, type === "REMOVED" ? value : undefined, type === "ADDED" ? value : undefined);
}

function walkStableArray(before, after, path, identityKey, beforeItems, afterItems, changes) {
  const identities = [...new Set([...beforeItems.keys(), ...afterItems.keys()])].sort();
  for (const identity of identities) {
    const itemPath = stableItemPath(path, identityKey, identity);
    const inBefore = beforeItems.has(identity);
    const inAfter = afterItems.has(identity);
    if (!inBefore) walkOneSided(afterItems.get(identity), itemPath, "ADDED", changes);
    else if (!inAfter) walkOneSided(beforeItems.get(identity), itemPath, "REMOVED", changes);
    else walk(beforeItems.get(identity), afterItems.get(identity), itemPath, changes);
  }

  if (beforeItems.size === afterItems.size
    && identities.every((identity) => beforeItems.has(identity) && afterItems.has(identity))) {
    const beforeOrder = before.map((item) => item[identityKey]);
    const afterOrder = after.map((item) => item[identityKey]);
    if (beforeOrder.some((identity, index) => identity !== afterOrder[index])) {
      changes.push(Object.freeze({
        type: "CHANGED",
        path: childPath(path, "@order"),
        before: orderValue(beforeOrder),
        after: orderValue(afterOrder),
      }));
    }
  }
}

function walk(before, after, path, changes) {
  if (before === after) return;

  const beforeArray = Array.isArray(before);
  const afterArray = Array.isArray(after);
  const beforeObject = isPlainObject(before);
  const afterObject = isPlainObject(after);

  if (beforeArray && afterArray) {
    const identityKey = STABLE_REPEATER_IDENTITIES.get(path);
    const beforeItems = identityKey ? stableItems(before, identityKey) : null;
    const afterItems = identityKey ? stableItems(after, identityKey) : null;
    if (identityKey && beforeItems && afterItems) {
      walkStableArray(before, after, path, identityKey, beforeItems, afterItems, changes);
      return;
    }
    const length = Math.max(before.length, after.length);
    for (let index = 0; index < length; index += 1) {
      const itemPath = childPath(path, String(index));
      if (index >= before.length) walkOneSided(after[index], itemPath, "ADDED", changes);
      else if (index >= after.length) walkOneSided(before[index], itemPath, "REMOVED", changes);
      else walk(before[index], after[index], itemPath, changes);
    }
    return;
  }

  if (beforeObject && afterObject) {
    const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
    for (const key of keys) {
      const propertyPath = childPath(path, key);
      if (!Object.hasOwn(before, key)) walkOneSided(after[key], propertyPath, "ADDED", changes);
      else if (!Object.hasOwn(after, key)) walkOneSided(before[key], propertyPath, "REMOVED", changes);
      else walk(before[key], after[key], propertyPath, changes);
    }
    return;
  }

  change(changes, "CHANGED", path, before, after);
}

function compareChanges(left, right) {
  const pathOrder = left.path < right.path ? -1 : left.path > right.path ? 1 : 0;
  if (pathOrder !== 0) return pathOrder;
  return CHANGE_ORDER[left.type] - CHANGE_ORDER[right.type];
}

/**
 * Compare two already-authorized EditorVersion.content projections.
 *
 * The result contains only stable paths and closed scalar/container summaries;
 * it never accepts or returns version, actor, role, workspace, or organization metadata.
 */
export function diffEditorVersionContent(before, after) {
  validateContent(before);
  validateContent(after);
  const changes = [];
  walk(before, after, "", changes);
  changes.sort(compareChanges);
  return Object.freeze({ equal: changes.length === 0, changes: Object.freeze(changes) });
}
