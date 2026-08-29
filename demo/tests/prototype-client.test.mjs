import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const clientUrl = new URL("../app/prototype-client.tsx", import.meta.url);

test("runAction catches domain-rule failures before handing state to React", async () => {
  const source = await readFile(clientUrl, "utf8");
  const start = source.indexOf("  function runAction(");
  const end = source.indexOf("\n  function loadScenario", start);
  const runAction = start >= 0 && end > start ? source.slice(start, end) : "";

  assert.ok(runAction, "expected to find the runAction implementation");
  assert.match(
    runAction,
    /try\s*{\s*const nextState = action\(state\);\s*setState\(nextState\);/,
    "the domain action must run synchronously inside runAction's try block",
  );
  assert.doesNotMatch(
    runAction,
    /setState\s*\(\s*\([^)]*\)\s*=>\s*action\(/,
    "a domain action inside a React state updater escapes runAction's catch block",
  );
});
