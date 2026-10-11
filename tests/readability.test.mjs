import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const css = await readFile(new URL("dist/styles.css", root), "utf8");
const marker = "/* Readability pass: keep the working lab legible at 100% browser zoom. */";
const readabilityPass = css.slice(css.indexOf(marker));

test("the working lab has an explicit 100 percent zoom readability pass", () => {
  assert.ok(css.includes(marker));
  assert.match(readabilityPass, /#policyEditor\s*\{[\s\S]*?font-size:\s*14px/);
  assert.match(readabilityPass, /\.finding-detail,[\s\S]*?font-size:\s*12px/);
  assert.match(readabilityPass, /\.proof-fields dt,[\s\S]*?font-size:\s*11px/);
  assert.match(
    readabilityPass,
    /\.report-verification li p\s*\{[\s\S]*?font-size:\s*11px/,
  );
  assert.match(
    readabilityPass,
    /\.report-verification li strong\s*\{[\s\S]*?font-size:\s*12px/,
  );
});
