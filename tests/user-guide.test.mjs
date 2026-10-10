import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const [html, css, app] = await Promise.all([
  readFile(new URL("dist/index.html", root), "utf8"),
  readFile(new URL("dist/styles.css", root), "utf8"),
  readFile(new URL("dist/app.js", root), "utf8"),
]);

test("the public page includes an accessible six-step user guide", () => {
  assert.match(html, /id="guideOpen"/);
  assert.match(html, /id="userGuide"[\s\S]*role="dialog"/);
  assert.match(html, /aria-modal="true"/);
  assert.equal((html.match(/class="guide-step"/g) || []).length, 6);
});

test("the guide is keyboard-aware and can start the sample flow", () => {
  assert.match(app, /function openGuide\(\)/);
  assert.match(app, /event\.key === "Escape"/);
  assert.match(app, /event\.key !== "Tab"/);
  assert.match(app, /templateSelect\.value = "unsafe"/);
  assert.match(css, /\.guide-backdrop\[hidden\]/);
});

test("the page does not contain duplicate element IDs", () => {
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
  assert.equal(ids.length, new Set(ids).size);
});
