// Cross-check: the Rust canonical form (verify/examples/vectors.rs) parses
// and re-serialises to the same bytes here; altered forms are refused.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { canonical, parse } from "./canonical.js";

const vectors = execFileSync("cargo", ["run", "-q", "--example", "vectors"], { cwd: new URL("..", import.meta.url).pathname })
  .toString().trim().split("\n");

test("Rust and JS agree on every vector", () => {
  assert.ok(vectors.length >= 4);
  for (const v of vectors) assert.equal(canonical(parse(v)), v);
});

test("non-canonical or altered requests are refused", () => {
  const v = vectors[1];
  const bad = [
    v.replace('"v":2,', '"v":2, '),                          // whitespace
    v.replace('{"v":2,', '{"v":2,"extra":1,'),              // extra field
    v.replace('"host":"office-pi",', ""),                 // missing field
    v.replace("\\u202e", "‮"),                          // raw non-ASCII
    v.replace("\\u00e9", "\\u00E9"),                         // upper-case hex
    v.replace('"created":1795100000', '"created":1795100000.0'),
    v.replace('"argv":["x"', '"argv":[1'),
    v.replace('"host":"office-pi","user":"claude"', '"user":"claude","host":"office-pi"'),
    v.replace('"v":2', '"v":3'),
    v + " ",
  ];
  for (const b of bad) {
    assert.notEqual(b, v);
    assert.throws(() => parse(b), undefined, b.slice(0, 80));
  }
});
