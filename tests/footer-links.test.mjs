import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const [html, css] = await Promise.all([
  readFile(new URL("dist/index.html", root), "utf8"),
  readFile(new URL("dist/styles.css", root), "utf8"),
]);

const footer = html.match(/<footer\b[\s\S]*?<\/footer>/)?.[0] ?? "";

const officialLinks = [
  "https://www.rialo.io/",
  "https://www.rialo.io/for-devs",
  "https://docs.rialo.io/",
  "https://playground.rialo.io/",
  "https://learn.rialo.io/",
  "https://x.com/RialoHQ",
  "https://discord.gg/RialoProtocol",
  "https://onlatch.com/",
  "https://onlatch.com/docs",
  "https://onlatch.com/docs/changelog",
  "https://onlatch.com/login?returnTo=/dashboard",
];

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

test("the footer exposes the verified Rialo and Latch destinations", () => {
  assert.ok(footer, "expected a page footer");

  for (const href of officialLinks) {
    assert.match(footer, new RegExp(`href="${escapeRegExp(href)}"`));
  }

  assert.doesNotMatch(footer, /href="https:\/\/github\.com\/rialo"/);
  assert.match(footer, /© 2026 LatchLens\. All rights reserved\./);
  assert.match(footer, /Independent builder project\./);
});

test("every external footer link opens safely", () => {
  const anchors = [...footer.matchAll(/<a\b[^>]*>/g)].map(([anchor]) => anchor);

  assert.equal(anchors.length, officialLinks.length);
  for (const anchor of anchors) {
    assert.match(anchor, /target="_blank"/);
    assert.match(anchor, /rel="noopener noreferrer"/);
  }
});

test("the expanded footer remains responsive and keyboard visible", () => {
  assert.match(css, /\.footer-main\s*{/);
  assert.match(css, /\.footer-links a:focus-visible/);
  assert.match(css, /\.footer-bottom\s*{/);
  assert.match(css, /\.footer-main\s*{[\s\S]*?grid-template-columns:\s*1fr 1fr;/);
});
