/* RAPP/1 primitives for the browser: canonical JSON, SHA-256, base64, particle/wave, RAPPIDs, Ed25519.
 * Mirrors vendor/rapp_hive2/rapp1.py byte for byte; tests/parity.mjs holds the two in lockstep.
 * No network, no eval, no innerHTML. Works from file://.
 */
(function (root) {
  "use strict";

  var MAX_DEPTH = 48;
  var MAX_JSON_BYTES = 1024 * 1024;
  var MAX_CARRIER_BYTES = 8 * 1024 * 1024;
  var MAX_MEMBERS = 10000;
  var SCHEMA_MAX_BYTES = 8 * 1024 * 1024;
  var FRAME_KEYS = ["frame_hash", "kind", "payload", "payload_hash", "prev", "prev_wave", "seq", "sig", "spec", "stream_id", "utc"];
  var HEAD_KEYS = ["stream_id", "seq", "payload_hash", "frame_hash"];
  var LCLABEL = "[a-z0-9]+(?:-[a-z0-9]+)*";
  var RAPPID_RE = new RegExp("^rappid:@(" + LCLABEL + ")/(" + LCLABEL + "):([0-9a-f]{64})$");
  var MEMORY_STREAM_RE = new RegExp("^(rappid:@" + LCLABEL + "/" + LCLABEL + ":[0-9a-f]{64}):(" + LCLABEL + ")$");
  var KIND_RE = new RegExp("^(" + LCLABEL + ")\\.(" + LCLABEL + ")$");
  var UTC_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{3}Z$/;
  var HASH_RE = /^[0-9a-f]{64}$/;

  function Refusal(code, message) {
    this.code = code;
    this.message = message;
  }
  Refusal.prototype.toString = function () { return this.code + ": " + this.message; };

  function LensExhaust(code, locus, detail) {
    this.code = code;
    this.locus = locus;
    this.detail = detail || {};
  }

  function hasLoneSurrogate(text) {
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        var d = text.charCodeAt(i + 1);
        if (!(d >= 0xdc00 && d <= 0xdfff)) return true;
        i++;
      } else if (c >= 0xdc00 && c <= 0xdfff) {
        return true;
      }
    }
    return false;
  }

  function canonString(value, depth) {
    if (depth > MAX_DEPTH) throw new Refusal("REFUSE_CANONICAL_JSON", "JSON nesting exceeds the bounded profile.");
    if (value === null) return "null";
    if (value === true) return "true";
    if (value === false) return "false";
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
        throw new Refusal("REFUSE_CANONICAL_JSON", "Only IEEE754 safe integers are allowed.");
      }
      return String(value);
    }
    if (typeof value === "string") {
      if (hasLoneSurrogate(value)) throw new Refusal("REFUSE_CANONICAL_JSON", "Unpaired Unicode surrogates are forbidden.");
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
      if (value.length > MAX_MEMBERS) throw new Refusal("REFUSE_CANONICAL_JSON", "JSON arrays exceed the bounded profile.");
      var parts = [];
      for (var i = 0; i < value.length; i++) parts.push(canonString(value[i], depth + 1));
      return "[" + parts.join(",") + "]";
    }
    if (typeof value === "object") {
      var keys = Object.keys(value).sort();
      if (keys.length > MAX_MEMBERS) throw new Refusal("REFUSE_CANONICAL_JSON", "Bounded string-keyed objects are required.");
      var out = [];
      for (var k = 0; k < keys.length; k++) {
        if (hasLoneSurrogate(keys[k])) throw new Refusal("REFUSE_CANONICAL_JSON", "Invalid Unicode object key.");
        out.push(JSON.stringify(keys[k]) + ":" + canonString(value[keys[k]], depth + 1));
      }
      return "{" + out.join(",") + "}";
    }
    throw new Refusal("REFUSE_CANONICAL_JSON", "Non-JSON value.");
  }

  var encoder = new TextEncoder();
  var decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

  function put(target, key, value) {
    Object.defineProperty(target, key, { value: value, enumerable: true, writable: true, configurable: true });
    return target;
  }

  /* Same byte limits as rapp_hive2/rapp1.py canonical(value, limit=...): 1 MiB unless a caller says otherwise. */
  function canonical(value, limit) {
    var bytes = encoder.encode(canonString(value, 0));
    if (bytes.length > (limit || MAX_JSON_BYTES)) throw new Refusal("REFUSE_JSON_SIZE", "JSON exceeds its byte limit.");
    return bytes;
  }

  function decodeUtf8(bytes) {
    try { return decoder.decode(bytes); } catch (e) { throw new Refusal("REFUSE_CANONICAL_JSON", "Invalid UTF-8."); }
  }

  /* Strict parse: canonical bytes are required, which also refuses floats,
   * duplicate keys, BOMs and noncanonical spacing (they cannot round-trip). */
  function parseCanonical(bytes, limit) {
    if (!bytes.length || bytes.length > (limit || MAX_JSON_BYTES)) throw new Refusal("REFUSE_JSON_SIZE", "JSON must be nonempty and bounded.");
    var text = decodeUtf8(bytes);
    var value;
    try { value = JSON.parse(text); } catch (e) { throw new Refusal("REFUSE_CANONICAL_JSON", "Invalid JSON."); }
    if (canonString(value, 0) !== text) throw new Refusal("REFUSE_CANONICAL_JSON", "Bytes are not exactly canonical (floats, duplicate keys, spacing or order).");
    return value;
  }

  /* ---- SHA-256: WebCrypto when available, a small pure fallback otherwise ---- */
  var K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function sha256Pure(bytes) {
    var h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    var length = bytes.length;
    var padded = new Uint8Array(((length + 9 + 63) >> 6) << 6);
    padded.set(bytes);
    padded[length] = 0x80;
    var bits = length * 8;
    var view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, Math.floor(bits / 0x100000000));
    view.setUint32(padded.length - 4, bits >>> 0);
    var w = new Uint32Array(64);
    for (var offset = 0; offset < padded.length; offset += 64) {
      for (var i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
      for (i = 16; i < 64; i++) {
        var x = w[i - 15], y = w[i - 2];
        var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    var out = "";
    for (i = 0; i < 8; i++) out += ("00000000" + h[i].toString(16)).slice(-8);
    return out;
  }

  function subtle() {
    return (root.crypto && root.crypto.subtle) ? root.crypto.subtle : null;
  }

  async function sha256Hex(bytes) {
    var s = subtle();
    if (s) {
      try {
        var digest = new Uint8Array(await s.digest("SHA-256", bytes));
        var hex = "";
        for (var i = 0; i < digest.length; i++) hex += ("0" + digest[i].toString(16)).slice(-2);
        return hex;
      } catch (e) { /* fall through to the pure implementation */ }
    }
    return sha256Pure(bytes);
  }

  function concat(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a);
    out.set(b, a.length);
    return out;
  }

  function hashValue(space, value, limit) { return sha256Hex(concat(encoder.encode(space + "\n"), canonical(value, limit))); }
  function particle(payload, limit) { return hashValue("rapp/1:particle", payload, limit); }
  function wave(frame) {
    var copy = {};
    Object.keys(frame).forEach(function (key) { if (key !== "frame_hash" && key !== "sig") put(copy, key, frame[key]); });
    return hashValue("rapp/1:wave", copy);
  }
  function head(frame) { var out = {}; HEAD_KEYS.forEach(function (k) { put(out, k, frame[k]); }); return out; }

  function b64decode(text) {
    if (typeof text !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) {
      throw new Refusal("REFUSE_ENCODING", "Invalid base64.");
    }
    var binary = atob(text);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }
  function b64urlDecode(text) {
    if (typeof text !== "string" || !/^[A-Za-z0-9_-]+$/.test(text)) throw new Refusal("REFUSE_SIGNATURE", "Invalid base64url.");
    var padded = text.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) padded += "=";
    var bytes;
    try { bytes = b64decode(padded); } catch (e) { throw new Refusal("REFUSE_SIGNATURE", "Invalid base64url."); }
    if (b64urlEncode(bytes) !== text) throw new Refusal("REFUSE_SIGNATURE", "Noncanonical base64url is forbidden.");
    return bytes;
  }
  function b64encode(bytes) {
    var binary = "";
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  function b64urlEncode(bytes) { return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }

  function checkRappid(rappid) {
    var match = typeof rappid === "string" ? RAPPID_RE.exec(rappid) : null;
    if (!match || match[1].length > 39 || match[2].length > 100) throw new Refusal("REFUSE_IDENTITY", "A canonical keyed RAPP identity is required.");
    return rappid;
  }

  function utcValid(value) {
    var match = typeof value === "string" ? UTC_RE.exec(value) : null;
    if (!match) return false;
    var year = Number(match[1]), month = Number(match[2]), day = Number(match[3]);
    var hour = Number(match[4]), minute = Number(match[5]), second = Number(match[6]);
    var leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    var days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    return year >= 1 && month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1] && hour <= 23 && minute <= 59 && second <= 59;
  }

  function streamFamily(stream) {
    if (typeof stream !== "string") return null;
    var memory = MEMORY_STREAM_RE.exec(stream);
    if (memory) {
      var owner = RAPPID_RE.exec(memory[1]);
      return owner[1].length <= 39 && owner[2].length <= 100 && memory[2].length <= 64 ? "memory" : null;
    }
    var body = RAPPID_RE.exec(stream);
    return body && body[1].length <= 39 && body[2].length <= 100 ? "body" : null;
  }

  async function frameIntegrity(frame) {
    var keys = Object.keys(frame || {}).sort();
    if (!isObj(frame) || JSON.stringify(keys) !== JSON.stringify(FRAME_KEYS)) throw new Refusal("REFUSE_FRAME_SHAPE", "An exact eleven-key RAPP/1 frame is required.");
    var kind = typeof frame.kind === "string" ? KIND_RE.exec(frame.kind) : null;
    if (frame.spec !== "rapp/1" || !kind || kind[1].length > 64 || kind[2].length > 64) {
      throw new Refusal("REFUSE_FRAME_SHAPE", "Invalid RAPP/1 frame envelope (spec or kind grammar).");
    }
    if (streamFamily(frame.stream_id) === null) throw new Refusal("REFUSE_FRAME_SHAPE", "rapp-hive/2 carries RAPP/1 memory and body streams only.");
    if (!Number.isSafeInteger(frame.seq) || frame.seq < 0) throw new Refusal("REFUSE_FRAME_SHAPE", "Invalid frame sequence.");
    if (!utcValid(frame.utc)) throw new Refusal("REFUSE_FRAME_TIME", "RAPP/1 requires a real UTC moment with exactly three milliseconds.");
    if (!isObj(frame.payload)) throw new Refusal("REFUSE_FRAME_SHAPE", "Frame payloads are JSON objects.");
    if (frame.prev_wave !== null) throw new Refusal("REFUSE_FRAME_SHAPE", "prev_wave is null off swarm (RAPP/1 wire chain).");
    if ((frame.seq === 0) !== (frame.prev === null) || (frame.prev !== null && (typeof frame.prev !== "string" || !HASH_RE.test(frame.prev)))) {
      throw new Refusal("REFUSE_HISTORY_ORDER", "Invalid genesis or particle predecessor.");
    }
    if (frame.payload_hash !== await particle(frame.payload)) throw new Refusal("REFUSE_FRAME_HASH", "RAPP/1 particle hash verification failed.");
    if (frame.frame_hash !== await wave(frame)) throw new Refusal("REFUSE_FRAME_HASH", "RAPP/1 wave hash verification failed.");
    return head(frame);
  }

  function jwsKid(frame) {
    var pieces = typeof frame.sig === "string" && frame.sig.length <= 16384 ? frame.sig.split(".") : [];
    if (pieces.length !== 3) throw new Refusal("REFUSE_SIGNATURE", "An exact detached unencoded EdDSA JWS is required.");
    var header = pieces[0] ? parseCanonical(b64urlDecode(pieces[0]), 4096) : null;
    if (!isObj(header) || !sameKeys(header, ["alg", "b64", "crit", "kid"])) {
      throw new Refusal("REFUSE_SIGNATURE", "The JWS protected header is exactly {alg, b64, crit, kid}.");
    }
    return checkRappid(header.kid);
  }

  function streamSigner(frame) {
    var family = streamFamily(frame.stream_id);
    if (family === "memory") return [checkRappid(MEMORY_STREAM_RE.exec(frame.stream_id)[1]), false];
    if (family === "body") return [jwsKid(frame), true];
    throw new Refusal("REFUSE_FRAME_SHAPE", "rapp-hive/2 carries RAPP/1 memory and body streams only.");
  }

  async function rappidMatches(rappid, spkiBytes) {
    var m = typeof rappid === "string" ? RAPPID_RE.exec(rappid) : null;
    if (!m || m[1].length > 39 || m[2].length > 100) return false;
    return m[3] === await sha256Hex(concat(encoder.encode("rapp/1:rappid\n"), spkiBytes));
  }

  var ed25519Support = null;
  async function ed25519Available() {
    if (ed25519Support !== null) return ed25519Support;
    var s = subtle();
    if (!s) { ed25519Support = false; return false; }
    try {
      var probe = b64decode("MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=");
      await s.importKey("spki", probe, { name: "Ed25519" }, false, ["verify"]);
      ed25519Support = true;
    } catch (e) {
      ed25519Support = false;
    }
    return ed25519Support;
  }

  /* Returns "verified", "unsupported" (browser lacks Ed25519) or throws a Refusal. */
  async function verifySignature(frame, spkiB64, signer) {
    if (typeof spkiB64 !== "string" || !spkiB64 || spkiB64.length > 1024) throw new Refusal("REFUSE_IDENTITY", "A bounded public Ed25519 SPKI is required.");
    var spki;
    try { spki = b64decode(spkiB64); } catch (e) { throw new Refusal("REFUSE_IDENTITY", "Invalid public Ed25519 SPKI."); }
    if (b64encode(spki) !== spkiB64) throw new Refusal("REFUSE_IDENTITY", "Only canonical base64 SPKI is supported.");
    if (!await rappidMatches(signer, spki)) throw new Refusal("REFUSE_IDENTITY", "The identity does not match its public key.");
    var pieces = typeof frame.sig === "string" && frame.sig.length <= 16384 ? frame.sig.split(".") : [];
    if (pieces.length !== 3 || pieces[1] !== "") throw new Refusal("REFUSE_SIGNATURE", "An exact detached EdDSA JWS is required.");
    var header = decodeUtf8(b64urlDecode(pieces[0]));
    if (header !== canonString({ alg: "EdDSA", b64: false, crit: ["b64"], kid: signer }, 0)) {
      throw new Refusal("REFUSE_SIGNATURE", "The signature was made for a different signer.");
    }
    if (b64urlDecode(pieces[2]).length !== 64) throw new Refusal("REFUSE_SIGNATURE", "Ed25519 signatures must be 64 bytes.");
    if (!await ed25519Available()) return "unsupported";
    var unsigned = {};
    Object.keys(frame).forEach(function (k) { if (k !== "sig") put(unsigned, k, frame[k]); });
    var data = concat(encoder.encode(pieces[0] + "."), canonical(unsigned));
    var key;
    try { key = await subtle().importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]); }
    catch (e) { throw new Refusal("REFUSE_IDENTITY", "Invalid public Ed25519 SPKI."); }
    var ok = await subtle().verify({ name: "Ed25519" }, key, b64urlDecode(pieces[2]), data);
    if (!ok) throw new Refusal("REFUSE_SIGNATURE", "The Ed25519 signature does not verify.");
    return "verified";
  }

  /* ---- Typed helpers (Python dict semantics, own properties only) ---- */
  function hasOwn(obj, key) { return obj !== null && typeof obj === "object" && Object.prototype.hasOwnProperty.call(obj, key); }
  function own(obj, key) { return hasOwn(obj, key) ? obj[key] : undefined; }
  function isObj(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
  function malformed(what) { return new Refusal("REFUSE_SCHEMA", "The carrier is malformed (" + what + ")."); }
  function req(obj, key) { if (!isObj(obj) || !hasOwn(obj, key)) throw malformed(key); return obj[key]; }
  function reqObj(obj, key) { var value = req(obj, key); if (!isObj(value)) throw malformed(key); return value; }
  function reqArr(obj, key) { var value = req(obj, key); if (!Array.isArray(value)) throw malformed(key); return value; }
  /* dict.get(key, fallback): fails on non-objects like Python's AttributeError would */
  function pyGet(obj, key, fallback) {
    if (!isObj(obj)) throw malformed(key);
    return hasOwn(obj, key) ? obj[key] : (fallback === undefined ? null : fallback);
  }
  function sameJson(a, b) { return canonString(a, 0) === canonString(b, 0); }
  function cmpCodePoints(a, b) {
    var i = 0, j = 0;
    while (i < a.length && j < b.length) {
      var x = a.codePointAt(i), y = b.codePointAt(j);
      if (x !== y) return x < y ? -1 : 1;
      i += x > 0xffff ? 2 : 1;
      j += y > 0xffff ? 2 : 1;
    }
    return i < a.length ? 1 : j < b.length ? -1 : 0;
  }
  function sortedCodePoints(list) { return list.slice().sort(cmpCodePoints); }
  function sameKeys(obj, keys) { return sameJson(sortedCodePoints(Object.keys(obj)), sortedCodePoints(keys)); }
  function unb64(text) {
    if (typeof text !== "string" || !text || text.length > Math.floor(MAX_JSON_BYTES * 4 / 3) + 4) throw new Refusal("REFUSE_ENCODING", "Bounded canonical base64 is required.");
    var bytes = b64decode(text);
    if (b64encode(bytes) !== text || bytes.length > MAX_JSON_BYTES) throw new Refusal("REFUSE_ENCODING", "Noncanonical or oversized base64.");
    return bytes;
  }

  root.RAPP1 = {
    Refusal: Refusal, LensExhaust: LensExhaust, MAX_DEPTH: MAX_DEPTH, MAX_JSON_BYTES: MAX_JSON_BYTES, MAX_CARRIER_BYTES: MAX_CARRIER_BYTES,
    MAX_MEMBERS: MAX_MEMBERS, SCHEMA_MAX_BYTES: SCHEMA_MAX_BYTES, FRAME_KEYS: FRAME_KEYS, HEAD_KEYS: HEAD_KEYS, UTC_RE: UTC_RE, HASH_RE: HASH_RE, KIND_RE: KIND_RE,
    canonString: function (v) { return canonString(v, 0); }, canonical: canonical, parseCanonical: parseCanonical, decodeUtf8: decodeUtf8,
    put: put, sha256Hex: sha256Hex, sha256Pure: sha256Pure, hashValue: hashValue, particle: particle, wave: wave, head: head,
    b64decode: b64decode, b64encode: b64encode, b64urlDecode: b64urlDecode, b64urlEncode: b64urlEncode, unb64: unb64,
    frameIntegrity: frameIntegrity, checkRappid: checkRappid, utcValid: utcValid, streamFamily: streamFamily, streamSigner: streamSigner, jwsKid: jwsKid,
    rappidMatches: rappidMatches, ed25519Available: ed25519Available, verifySignature: verifySignature,
    hasOwn: hasOwn, own: own, isObj: isObj, sameJson: sameJson, cmpCodePoints: cmpCodePoints, sortedCodePoints: sortedCodePoints, sameKeys: sameKeys
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
