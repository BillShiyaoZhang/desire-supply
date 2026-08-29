import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the Foundations synthetic prototype boundary and scenarios", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<html[^>]+lang="zh-CN"/i);
  assert.match(html, /<title>愿作 · 制度原型<\/title>/i);
  assert.match(html, /G0A/);
  assert.match(html, /G1[^<]*NO-GO/);
  assert.match(html, /G2[^<]*NO-GO/);
  assert.match(html, /完全合成/);
  assert.match(html, /不是服务入口/);
  assert.match(html, /正常旅程/);
  assert.match(html, /拒绝不惩罚/);
  assert.match(html, /付款结果未知/);
  assert.match(html, /独立申诉/);
  assert.match(html, /数据退出/);
  assert.match(html, /本次会话内只追加的合成事件列表/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|Building your site/i);
  assert.doesNotMatch(html, /电子签署|不可篡改账本|真实到账|已执行真实删除/);
  assert.doesNotMatch(html, /compensationFloor|schedulingNotes|private synthetic fixture/);
});

test("removes starter preview code, metadata, and hosting hooks", async () => {
  const [page, layout, packageJson, css, viteConfig] = await Promise.all([
    readFile(new URL("app/page.tsx", root), "utf8"),
    readFile(new URL("app/layout.tsx", root), "utf8"),
    readFile(new URL("package.json", root), "utf8"),
    readFile(new URL("app/globals.css", root), "utf8"),
    readFile(new URL("vite.config.ts", root), "utf8"),
  ]);
  assert.doesNotMatch(page, /SkeletonPreview|codex-preview/);
  assert.doesNotMatch(layout, /Starter Project|lang="en"/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(css, /forced-colors/);
  assert.doesNotMatch(viteConfig, /hosting\.json|sites-vite-plugin|sites\(\)/);
  await assert.rejects(access(new URL("app/_sites-preview", root)));
  await assert.rejects(access(new URL("app/chatgpt-auth.ts", root)));
  await assert.rejects(access(new URL("postcss.config.mjs", root)));
  await assert.rejects(access(new URL(".openai/hosting.json", root)));
  await assert.rejects(access(new URL("build/sites-vite-plugin.ts", root)));
  await assert.rejects(access(new URL("dist/.openai/hosting.json", root)));
});
