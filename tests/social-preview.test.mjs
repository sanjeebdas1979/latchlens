import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const html = await readFile(new URL("dist/index.html", root), "utf8");
const image = await readFile(new URL("dist/og-latchlens.jpg", root));

test("the public page exposes a complete large social preview", () => {
  assert.match(html, /<link rel="canonical" href="https:\/\/www\.latchlens\.xyz\/" \/>/);
  assert.match(html, /property="og:type" content="website"/);
  assert.match(
    html,
    /property="og:image"[\s\S]*?content="https:\/\/www\.latchlens\.xyz\/og-latchlens\.jpg"/,
  );
  assert.match(html, /property="og:image:width" content="1200"/);
  assert.match(html, /property="og:image:height" content="630"/);
  assert.match(html, /name="twitter:card" content="summary_large_image"/);
  assert.match(
    html,
    /name="twitter:image"[\s\S]*?content="https:\/\/www\.latchlens\.xyz\/og-latchlens\.jpg"/,
  );
  assert.match(html, /property="og:image:alt"/);
  assert.match(html, /name="twitter:image:alt"/);
});

test("the social preview asset is an exact 1200 by 630 JPEG", () => {
  assert.equal(image[0], 0xff);
  assert.equal(image[1], 0xd8);

  let offset = 2;
  let width;
  let height;

  while (offset < image.length) {
    assert.equal(image[offset], 0xff);
    const marker = image[offset + 1];
    offset += 2;

    if (marker === 0xd8 || marker === 0xd9) continue;

    const segmentLength = image.readUInt16BE(offset);
    const isStartOfFrame = [
      0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7,
      0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf,
    ].includes(marker);

    if (isStartOfFrame) {
      height = image.readUInt16BE(offset + 3);
      width = image.readUInt16BE(offset + 5);
      break;
    }

    offset += segmentLength;
  }

  assert.equal(width, 1200);
  assert.equal(height, 630);
});
