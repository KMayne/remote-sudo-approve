// The request's canonical form, mirroring verify/src/request.rs exactly.
// The page signs SHA-256 of the bytes it received only if parsing them and
// re-serialising here gives the same bytes back, so every byte that is
// signed was parsed, checked and shown.

const HEX = "0123456789abcdef";

/** A JSON string literal, ASCII only: `"` and `\` escaped, everything
 * outside printable ASCII as \uXXXX per UTF-16 code unit. */
export function escape(s) {
  let o = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) o += '\\"';
    else if (c === 0x5c) o += "\\\\";
    else if (c >= 0x20 && c <= 0x7e) o += s[i];
    else o += "\\u" + HEX[(c >> 12) & 15] + HEX[(c >> 8) & 15] + HEX[(c >> 4) & 15] + HEX[c & 15];
  }
  return o + '"';
}

const isStr = (x) => typeof x === "string";
const isUint = (x) => Number.isSafeInteger(x) && x >= 0;
const isStrArray = (x) => Array.isArray(x) && x.every(isStr);
const isPairs = (x) => Array.isArray(x) && x.every((p) => Array.isArray(p) && p.length === 2 && isStr(p[0]) && isStr(p[1]));
const sameKeys = (o, keys) => o && typeof o === "object" && !Array.isArray(o) &&
  Object.keys(o).length === keys.length && keys.every((k, i) => Object.keys(o)[i] === k);

const FIELDS = ["v", "id", "host", "user", "runas", "command", "argv", "env", "cwd", "stdin", "created", "expires", "change", "warnings"];

/** Parse and validate the request text. Returns the object, or throws. */
export function parse(text) {
  if (!/^[\x20-\x7e]*$/.test(text)) throw new Error("request is not printable ASCII");
  const r = JSON.parse(text);
  if (!sameKeys(r, FIELDS)) throw new Error("request has unexpected fields");
  if (r.v !== 2) throw new Error("unknown request version");
  for (const k of ["id", "host", "user", "runas", "command", "cwd", "stdin"]) {
    if (!isStr(r[k])) throw new Error(`bad ${k}`);
  }
  if (!isStrArray(r.argv) || r.argv.length === 0) throw new Error("bad argv");
  if (!isPairs(r.env)) throw new Error("bad env");
  if (!isUint(r.created) || !isUint(r.expires)) throw new Error("bad times");
  if (!isStrArray(r.warnings)) throw new Error("bad warnings");
  if (r.change !== null) {
    if (!sameKeys(r.change, ["system", "diffs"]) || !isStr(r.change.system) || !isPairs(r.change.diffs)) {
      throw new Error("bad change");
    }
  }
  if (canonical(r) !== text) throw new Error("request is not in canonical form");
  return r;
}

const arr = (xs) => "[" + xs.map(escape).join(",") + "]";

export function canonical(r) {
  let o = '{"v":' + r.v;
  for (const k of ["id", "host", "user", "runas", "command"]) o += `,"${k}":` + escape(r[k]);
  o += ',"argv":' + arr(r.argv);
  o += ',"env":[' + r.env.map(arr).join(",") + "]";
  o += ',"cwd":' + escape(r.cwd);
  o += ',"stdin":' + escape(r.stdin);
  o += ',"created":' + r.created + ',"expires":' + r.expires;
  o += ',"change":' + (r.change === null ? "null" :
    '{"system":' + escape(r.change.system) + ',"diffs":[' + r.change.diffs.map(arr).join(",") + "]}");
  o += ',"warnings":' + arr(r.warnings) + "}";
  return o;
}
