import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const css = await readFile(new URL("dist/styles.css", root), "utf8");
const marker =
  "/* Premium card borders: a quiet highlight glides around each primary surface. */";
const premiumPass = css.slice(css.indexOf(marker));

test("primary cards use a smooth masked gliding border", () => {
  assert.ok(css.includes(marker));
  assert.match(premiumPass, /@property --premium-border-angle/);
  assert.match(premiumPass, /@keyframes premium-border-glide/);
  assert.match(premiumPass, /\.hero-visual,[\s\S]*?\.panel,[\s\S]*?\.value-card/);
  assert.match(premiumPass, /\.flow-node,[\s\S]*?\.roadmap-note,[\s\S]*?\.guide-step/);
  assert.match(premiumPass, /mask-composite:\s*exclude/);
  assert.match(premiumPass, /pointer-events:\s*none/);
  assert.match(
    premiumPass,
    /animation:\s*premium-border-glide 8s linear infinite/,
  );
});

test("premium card motion respects reduced-motion preferences", () => {
  assert.match(
    css,
    /@media \(prefers-reduced-motion: reduce\)[\s\S]*?animation-duration:\s*0\.01ms !important/,
  );
  assert.match(
    css,
    /@media \(prefers-reduced-motion: reduce\)[\s\S]*?animation-iteration-count:\s*1 !important/,
  );
});
