import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import { spawnSync } from "node:child_process";
import vm from "node:vm";

// --differential compares declaration and schema mutations with the vendored Python, without writing files.
const context = vm.createContext({ TextEncoder, TextDecoder, crypto: webcrypto, atob, btoa, console });
for (const name of ["rapp1-primitives.js", "rapp_hive2.js"]) {
  vm.runInContext(await readFile(new URL("../app/src/" + name, import.meta.url), "utf8"), context, { filename: name });
}
const R = context.RAPP1, H = context.RAPPHIVE2;
const vectors = JSON.parse(await readFile(new URL("../conformance/vectors.json", import.meta.url), "utf8"));
const summary = { passed: 0, failed: [] };
const canonical = (value) => R.decodeUtf8(R.canonical(value));

function make(recipe) {
  const [[kind, size]] = Object.entries(recipe);
  if (kind === "string") return "x".repeat(size);
  if (kind === "array") return Array(size).fill(0);
  if (kind === "nested") {
    let value = [];
    for (let index = 1; index < size; index++) value = [value];
    return value;
  }
  throw new Error("Unknown make recipe: " + kind);
}

async function outcome(work) {
  try { return await work(); }
  catch (error) {
    if (!(error instanceof R.Refusal)) throw error;
    return { refused: error.code };
  }
}

async function check(label, work) {
  try {
    await work();
    summary.passed++;
  } catch (error) {
    summary.failed.push(label + ": " + (error.message || String(error)));
  }
}

function same(actual, expected) {
  const got = canonical(actual), want = canonical(expected);
  if (got !== want) {
    let offset = 0;
    while (got[offset] === want[offset]) offset++;
    throw new Error("mismatch at byte/string offset " + offset + "; expected " + want.slice(offset, offset + 200) + "; got " + got.slice(offset, offset + 200));
  }
}

async function differential() {
  const files = vectors.hives.find((item) => item.name === "model").files;
  const declaration = Object.entries(files).filter(([name]) => name.startsWith("streams/"))
    .map(([, data]) => R.parseCanonical(R.b64decode(data))).find((frame) => frame.kind === "hive.declaration").payload;
  const copy = (value) => JSON.parse(JSON.stringify(value));
  const cases = [];
  function add(label, mutate, accepted) {
    const value = copy(declaration);
    mutate(value);
    cases.push({ label, method: "declaration", value, ...(accepted === undefined ? {} : { accepted }) });
  }
  function set(path, value, accepted) {
    add(path.join(".") + " = " + JSON.stringify(value).slice(0, 90), (payload) => {
      let parent = payload;
      for (const key of path.slice(0, -1)) parent = parent[key];
      parent[path[path.length - 1]] = copy(value);
    }, accepted);
  }
  add("unchanged model declaration", () => {}, true);
  const paths = [
    ...Object.keys(declaration).map((key) => [key]),
    ["members", 0], ...["rappid", "role", "area"].map((key) => ["members", 0, key]),
    ["rooms", 0], ...["id", "area", "members", "access"].map((key) => ["rooms", 0, key]),
    ["channels", 0], ...["id", "kind", "role", "locator", "writeback"].map((key) => ["channels", 0, key]),
    ...Object.keys(declaration.policy).map((key) => ["policy", key])
  ];
  for (const path of paths) for (const value of [null, false, true, 0, 1, "", "wrong", [], {}, ["owner"]]) set(path, value);
  for (const key of Object.keys(declaration)) add("missing " + key, (payload) => { delete payload[key]; }, false);
  for (const path of [["members", 0], ["rooms", 0], ["channels", 0], ["policy"]]) {
    let object = declaration;
    for (const key of path) object = object[key];
    for (const key of Object.keys(object)) add("missing " + path.join(".") + "." + key, (payload) => {
      let parent = payload;
      for (const part of path) parent = parent[part];
      delete parent[key];
    }, false);
    add("extra key in " + path.join("."), (payload) => {
      let parent = payload;
      for (const part of path) parent = parent[part];
      parent.extra = "synthetic";
    }, false);
  }
  add("extra root key", (payload) => { payload.extra = "synthetic"; }, false);
  add("NFD key before missing fields", (payload) => { delete payload.rooms; payload["cafe\u0301"] = "value"; }, false);
  add("NFD nested key before member shape", (payload) => { payload.members[0]["cafe\u0301"] = "value"; }, false);
  add("NFD in malformed nested array", (payload) => { payload.rooms = [{ extra: [["cafe\u0301"]] }]; }, false);
  for (const value of ["cafe\u0301", "A\u030a", "\u1100\u1161", "\u212b"]) {
    for (const path of [["members", 0, "area"], ["rooms", 0, "area"], ["channels", 0, "locator"]]) set(path, value, false);
  }
  for (const value of ["a", "a--b", "a---b", "a".repeat(64), "a".repeat(65), "-a", "a-", "A", "a_b", "a.b"]) set(["world_id"], value);
  add("adjacent hyphens in world label", (payload) => { payload.world_id = "a--b"; }, true);
  add("adjacent hyphens in room label", (payload) => {
    payload.rooms[0].id = "a--b";
    payload.rooms.sort((a, b) => R.cmpCodePoints(a.id, b.id));
  }, true);
  add("adjacent hyphens in named authority", (payload) => {
    payload.channels.find((channel) => channel.role === "authority").id = "a--b";
    payload.authority_channel_id = "a--b";
    payload.channels.sort((a, b) => R.cmpCodePoints(a.id, b.id));
  }, true);
  for (const stamp of ["0000-01-01T00:00:00.000Z", "1900-02-29T00:00:00.000Z", "2000-02-29T00:00:00.000Z", "2026-04-31T00:00:00.000Z", "2026-09-23T24:00:00.000Z"]) {
    set(["created_utc"], stamp);
  }
  const reserved = ["CON", "PRN", "AUX", "NUL", ...Array.from({ length: 9 }, (_, i) => "COM" + (i + 1)), ...Array.from({ length: 9 }, (_, i) => "LPT" + (i + 1))];
  for (const path of [["members", 0, "area"], ["rooms", 0, "area"]]) {
    for (const name of reserved) for (const value of [name, name.toLowerCase(), name + ".json", "rooms/" + name, "rooms/" + name.toLowerCase() + ".txt"]) set(path, value, false);
    for (const value of ["/absolute", "a\\b", "C:", "C:area", "C:/area", "z:\\area", "a/C:area", "a:b", ".", "..", "a/../b", "a/./b", "a//b", "a/", "a ", "a.", "a /b", "a./b", "a\x00b", "a\x1fb", "a\x7fb"]) set(path, value, false);
    for (const value of ["a/b", "COM0", "COM10", "LPT10", "CONSOLE", ".NUL", " leading-space", "a?b", "a<b", "caf\u00e9", "\u{1f600}", "\u{1f600}".repeat(1024), "root/" + "\u{1f600}".repeat(1019)]) set(path, value, true);
    set(path, "\u{1f600}".repeat(1025), false);
    set(path, "a".repeat(1024), true);
    set(path, "a".repeat(1025), false);
  }
  for (const value of ["caf\u00e9", "\u{1f600}", "\u{1f600}".repeat(2048), "a".repeat(2048), "local:\x00\x7f"]) set(["channels", 0, "locator"], value, true);
  for (const value of ["", "\u{1f600}".repeat(2049), "a".repeat(2049)]) set(["channels", 0, "locator"], value, false);
  add("duplicate members", (payload) => { payload.members.push(copy(payload.members[0])); }, false);
  add("unsorted members", (payload) => { payload.members.reverse(); }, false);
  add("no owner", (payload) => { payload.members.forEach((member) => { member.role = "member"; }); }, false);
  add("multiple owners", (payload) => { payload.members.forEach((member) => { member.role = "owner"; }); }, false);
  add("unknown room member", (payload) => { payload.rooms[0].members = ["rappid:@contoso/outsider:" + "0".repeat(64)]; }, false);
  add("duplicate room members", (payload) => { payload.rooms[0].members.push(payload.rooms[0].members[0]); }, false);
  add("unsorted room audience", (payload) => { payload.rooms[0].members = payload.members.map((member) => member.rappid).reverse(); }, false);
  for (const collection of ["rooms", "channels"]) {
    add("duplicate " + collection, (payload) => { payload[collection].push(copy(payload[collection][0])); }, false);
    add("unsorted " + collection, (payload) => {
      const next = { ...copy(payload[collection][0]), id: "z-final" };
      if (collection === "channels") next.role = "mirror";
      payload[collection] = [next, { ...payload[collection][0], id: "a-first" }];
      if (collection === "channels") payload.authority_channel_id = "a-first";
    }, false);
  }
  for (const kind of ["github", "sharepoint", "nas", "lan", "local", "custom"]) set(["channels", 0, "kind"], kind, true);
  for (const access of ["repository", "sealed"]) set(["rooms", 0, "access"], access, true);
  add("authority cannot disable writeback", (payload) => { payload.channels.find((channel) => channel.role === "authority").writeback = false; }, false);
  add("wrong named authority", (payload) => { payload.authority_channel_id = "not-present"; }, false);
  add("two authority channels", (payload) => {
    payload.channels.push({ ...copy(payload.channels.find((channel) => channel.role === "authority")), id: "z-authority" });
    payload.channels.sort((a, b) => R.cmpCodePoints(a.id, b.id));
  }, false);
  for (const role of ["writable", "mirror", "cache", "backup"]) add("supported secondary channel " + role, (payload) => {
    payload.channels.push({ id: "z-" + role, kind: "local", role, locator: "synthetic", writeback: false });
    payload.channels.sort((a, b) => R.cmpCodePoints(a.id, b.id));
  }, true);

  const baseSchema = H.schema.schema_of({ spec: "rapp/1", kind: "memory.save", payload: { operation: "task", title: "Synthetic" } });
  function schemaCase(label, value) { cases.push({ label, method: "schema", value: copy(value) }); }
  schemaCase("generated schema", baseSchema);
  for (const key of Object.keys(baseSchema)) {
    const value = copy(baseSchema);
    delete value[key];
    schemaCase("schema missing " + key, value);
  }
  for (const kind of ["a.b", "a".repeat(64) + "." + "b".repeat(64), "a".repeat(65) + ".b", "a." + "b".repeat(65), "a..b", "a--b.c", true, []]) schemaCase("schema kind " + kind, { ...baseSchema, kind });
  for (const tags of [{}, { profile: "demo", operation: "task" }, { unknown: "text" }, { profile: 1 }, [], null]) schemaCase("schema tag types", { ...baseSchema, tags });
  for (const payload of [null, [], "object", {}, { field: "object" }, { field: true }, { field: null }, { field: 1 }, { field: {} }, { field: [] },
    { field: ["integer", "string"] }, { field: ["string", "integer"] }, { field: ["integer", "integer"] },
    { field: ["null", [], {}] }, { field: [{ "\uffff": "string" }, { "\u{1f600}": "string" }] },
    { field: [{ "\u{1f600}": "string" }, { "\uffff": "string" }] }]) schemaCase("schema shape " + JSON.stringify(payload), { ...baseSchema, payload });
  const python = spawnSync("python3", ["-B", "-c", [
    "import json, sys",
    'sys.path.insert(0, "vendor")',
    "from rapp_hive2 import hive, schema",
    "from rapp_hive2.rapp1 import Refusal",
    "def check(case):",
    "    if case['method'] == 'declaration':",
    "        return hive.v1_declaration_problem(case['value'])",
    "    try:",
    "        schema.check_schema(case['value'])",
    "        return None",
    "    except Refusal as error:",
    "        return {'refused': error.code, 'message': error.message}",
    "print(json.dumps([check(case) for case in json.load(sys.stdin)]))"
  ].join("\n")], { cwd: new URL("../", import.meta.url), encoding: "utf8", input: JSON.stringify(cases), maxBuffer: 16 * 1024 * 1024, timeout: 60000, env: { ...process.env, PYTHONUTF8: "1", PYTHONDONTWRITEBYTECODE: "1" } });
  if (python.error) throw python.error;
  if (python.status !== 0) throw new Error("Python differential checks failed: " + python.stderr);
  const expected = JSON.parse(python.stdout);
  if (expected.length !== cases.length) throw new Error("Python returned an incomplete differential result.");
  for (const [index, item] of cases.entries()) {
    await check(item.label, async () => {
      let got = null;
      if (item.method === "declaration") got = H.v1_declaration_problem(item.value);
      else {
        try { H.schema.check_schema(item.value); }
        catch (error) {
          if (!(error instanceof R.Refusal)) throw error;
          got = { refused: error.code, message: error.message };
        }
      }
      same(got, expected[index]);
      if (typeof item.accepted === "boolean") same(got === null, item.accepted);
    });
  }
}

if (process.argv.includes("--differential")) {
  try { await differential(); }
  catch (error) { summary.failed.push("differential setup: " + (error.message || String(error))); }
} else if (!await R.ed25519Available()) {
  summary.failed.push("This Node runtime cannot check Ed25519 signatures.");
} else {
  for (const [index, item] of vectors.canonical.values.entries()) {
    await check("canonical " + (item.name || index), async () => {
      const value = item.make ? make(item.make) : JSON.parse(item.json);
      const got = await outcome(async () => ({ particle: await R.particle(value) }));
      same(got, item.expect || { particle: item.particle });
      if (item.canonical_b64 && R.b64encode(R.canonical(value)) !== item.canonical_b64) throw new Error("canonical bytes differ");
    });
  }
  for (const item of vectors.canonical.refused) {
    await check("refused " + item.why, async () => {
      try { R.parseCanonical(R.b64decode(item.b64)); }
      catch (error) {
        if (error instanceof R.Refusal) return;
        throw error;
      }
      throw new Error("the invalid bytes were accepted");
    });
  }
  for (const [index, item] of vectors.schemas.entries()) {
    await check("schema " + index, async () => {
      const frame = R.parseCanonical(R.b64decode(item.frame_b64));
      same(await H.schema.particle(H.schema.check_schema(H.schema.schema_of(frame))), item.schema_particle);
    });
  }
  const evaluations = new Map();
  for (const item of vectors.hives) {
    await check("hive " + item.name, async () => {
      const got = await outcome(async () => {
        const result = await H.evaluate(item.files);
        evaluations.set(item.name, result.evaluation);
        if (!result.verification.signature_support || result.verification.signatures !== result.records.length) {
          throw new Error("not every signature was checked");
        }
        for (const record of result.records) same([record.owner, record.legacy], R.streamSigner(record.frame));
        const evaluation = result.evaluation;
        if (Object.values(evaluation.pending).some((request) => R.hasOwn(evaluation.members, request.requester))) {
          throw new Error("an admitted member still has a pending request");
        }
        same(evaluation.quarantine.map((record) => record.wave), result.verdict.quarantined);
        if (evaluation.content.some((record) => !evaluation.final_members.has(record.owner)) ||
            evaluation.quarantine.some((record) => R.hasOwn(evaluation.frame_schema, record.wave))) {
          throw new Error("quarantined messages entered content processing or schema learning");
        }
        if (evaluation.quarantine.length && evaluation.state.members.length) {
          same(await outcome(() => H.cross_to_member(evaluation, evaluation.quarantine[0].wave, evaluation.state.members[0])), { refused: "REFUSE_CROSSING" });
        }
        return { verdict: result.verdict };
      });
      same(got, item.expect);
    });
  }
  for (const item of vectors.crossings) {
    await check("crossing " + item.source.slice(0, 12) + " -> " + item.member, async () => {
      const evaluation = evaluations.get(item.hive);
      if (!evaluation) throw new Error("the source Hive did not evaluate");
      const got = await outcome(async () => {
        const result = await H.cross_to_member(evaluation, item.source, item.member);
        return {
          payload_particle: result.payload_particle,
          not_expressible_in_target: result.not_expressible_in_target,
          lossless: result.lossless
        };
      });
      same(got, item.expect);
    });
  }
}
console.log(JSON.stringify(summary));
process.exitCode = summary.failed.length ? 1 : 0;
