import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";

const helperUrl = new URL(
  "../lib/organization-invitation-time.mjs",
  import.meta.url,
).href;
const FOURTEEN_DAYS_MS = 14 * 24 * 60 * 60 * 1000;

function evaluateInTimezone({ timezone, now, submittedLocal }) {
  const source = `
    import {
      defaultOrganizationInvitationExpiry,
      organizationInvitationExpiryToIso,
    } from ${JSON.stringify(helperUrl)};
    const now = Date.parse(${JSON.stringify(now)});
    const defaultLocal = defaultOrganizationInvitationExpiry(now);
    const defaultIso = organizationInvitationExpiryToIso(defaultLocal);
    const submittedIso = organizationInvitationExpiryToIso(${JSON.stringify(submittedLocal)});
    process.stdout.write(JSON.stringify({ defaultLocal, defaultIso, submittedIso }));
  `;
  return JSON.parse(execFileSync(process.execPath, [
    "--input-type=module",
    "--eval",
    source,
  ], {
    encoding: "utf8",
    env: { ...process.env, TZ: timezone },
  }));
}

test("organization invitation defaults remain exactly fourteen days in UTC and local timezones", () => {
  const cases = [
    {
      timezone: "UTC",
      now: "2026-01-15T12:30:00.000Z",
      expectedDefaultLocal: "2026-01-29T12:30",
      submittedLocal: "2026-02-03T09:45",
      expectedSubmittedIso: "2026-02-03T09:45:00.000Z",
    },
    {
      timezone: "Asia/Shanghai",
      now: "2026-01-15T12:30:00.000Z",
      expectedDefaultLocal: "2026-01-29T20:30",
      submittedLocal: "2026-02-03T09:45",
      expectedSubmittedIso: "2026-02-03T01:45:00.000Z",
    },
    {
      timezone: "America/New_York",
      now: "2026-03-01T17:30:00.000Z",
      expectedDefaultLocal: "2026-03-15T13:30",
      submittedLocal: "2026-03-15T09:45",
      expectedSubmittedIso: "2026-03-15T13:45:00.000Z",
    },
  ];

  for (const scenario of cases) {
    const result = evaluateInTimezone(scenario);
    const expectedDefaultIso = new Date(
      Date.parse(scenario.now) + FOURTEEN_DAYS_MS,
    ).toISOString();
    assert.equal(result.defaultLocal, scenario.expectedDefaultLocal, scenario.timezone);
    assert.equal(result.defaultIso, expectedDefaultIso, scenario.timezone);
    assert.equal(
      Date.parse(result.defaultIso) - Date.parse(scenario.now),
      FOURTEEN_DAYS_MS,
      scenario.timezone,
    );
    assert.equal(result.submittedIso, scenario.expectedSubmittedIso, scenario.timezone);
  }
});

test("organization invitation conversion rejects malformed or impossible local values", async () => {
  const { organizationInvitationExpiryToIso } = await import(helperUrl);
  for (const value of [
    "2026-02-30T09:45",
    "2026-01-15T24:00",
    "2026-01-15 09:45",
    "",
  ]) assert.throws(
    () => organizationInvitationExpiryToIso(value),
    /INVALID_EXPIRY/,
  );
});
