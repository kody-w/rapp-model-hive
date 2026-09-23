/* Browser port of the vendored rapp-hive/2 reference. Authority is derived, never read from the tour.
 * Hashing/verification are async; use await evaluate(files) or await Evaluation.create(...).
 * Files are a {relative_path: canonical_base64} bundle. No filesystem or network access.
 */
(function (root) {
  "use strict";

  const R = root.RAPP1;
  const { Refusal, LensExhaust, isObj, hasOwn } = R;
  const sorted = R.sortedCodePoints;
  const dictionary = () => Object.create(null);
  const keys = (value) => Object.keys(value);
  const exact = (value, names) => isObj(value) && R.sameKeys(value, names);
  const get = (value, key, fallback = null) => hasOwn(value, key) ? value[key] : fallback;
  const clone = (value) => JSON.parse(R.canonString(value));
  const textLength = (value) => Array.from(value).length;
  const equal = (left, right, limit = R.MAX_JSON_BYTES) => R.decodeUtf8(R.canonical(left, limit)) === R.decodeUtf8(R.canonical(right, limit));
  const hex = (value) => typeof value === "string" && value.length === 64 && R.HASH_RE.test(value);
  const identifier = (value) => typeof value === "string" && /^[a-z0-9]+(?:[-./][a-z0-9]+)*$/.test(value) && !value.endsWith("\n");
  const uniqueSorted = (value) => Array.isArray(value) && equal(value, sorted(Array.from(new Set(value))));
  const sortedUniqueStrings = (value) => Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === "string") && uniqueSorted(value);
  const positive = (value) => Number.isSafeInteger(value) && value >= 1;
  const SCHEMA = "rapp-schema/1";
  const TAG_KEYS = ["schema", "profile", "operation"];
  const VIEW = "rapp-hive/2-view";
  const LENS = "rapp-hive/2-lens";
  const ANCHOR = "rapp-hive/2-anchor";
  const POLICY = "rapp-hive/2-policy";
  const IDENTITY = "rapp-hive/2-identity";
  const STATE = "rapp-hive/2-state";
  const VERDICT = "rapp-hive/2-verdict";
  const ALL_MEMBERS = "members";
  const LEGACY_V1 = "rapp-hive/1";
  const V1_DECLARATION_KEYS = ["schema", "hive_rappid", "world_id", "created_utc", "authority_channel_id", "members", "rooms", "channels", "policy"];
  const V1_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
  const V1_ROLES = ["owner", "member", "viewer"];
  const V1_ROOM_ACCESS = ["repository", "sealed"];
  const V1_CHANNEL_KINDS = ["github", "sharepoint", "nas", "lan", "local", "custom"];
  const V1_CHANNEL_ROLES = ["authority", "writable", "mirror", "cache", "backup"];
  const V1_PRIVACY = {
    godd_sharing: "explicit", default_godd_scope: "local-only", external_publication: "disabled",
    conflict_mode: "explicit", default_transfer: "copy"
  };
  const TYPES = ["array", "boolean", "integer", "null", "object", "string"];
  const TYPE_NAMES = ["null", "boolean", "integer", "string"];
  const MAX_FILES = 20000;
  const KINDS = {
    "hive2.accept": ["rapp-hive/2-accept", ["schema", "anchor"]],
    "hive2.join": ["rapp-hive/2-join", ["schema", "anchor", "policy"]],
    "hive2.grant": ["rapp-hive/2-grant", ["schema", "anchor", "member", "request"]],
    "hive2.adopt": ["rapp-hive/2-adopt", ["schema", "anchor", "object", "predecessor"]],
    "hive2.attest": ["rapp-hive/2-attest", ["schema", "anchor", "subject", "claim", "method"]],
    "hive2.manifest": ["rapp-hive/2-manifest", ["schema", "anchor", "heads", "state"]]
  };

  function shape(value) {
    if (isObj(value)) {
      const out = dictionary();
      for (const key of keys(value)) out[key] = shape(value[key]);
      return out;
    }
    if (Array.isArray(value)) {
      const unique = new Map();
      for (const element of value) {
        const item = shape(element);
        unique.set(R.decodeUtf8(R.canonical(item, R.SCHEMA_MAX_BYTES)), item);
      }
      return sorted(Array.from(unique.keys())).map((key) => unique.get(key));
    }
    if (value === null) return "null";
    if (typeof value === "boolean") return "boolean";
    if (Number.isInteger(value)) return "integer";
    if (typeof value === "string") return "string";
    throw new Refusal("REFUSE_SCHEMA", "Only JSON values have a schema.");
  }

  function schemaOf(frame) {
    if (!isObj(frame) || !isObj(frame.payload)) throw new Refusal("REFUSE_FRAME_SHAPE", "Frame payloads are JSON objects.");
    const tags = dictionary();
    for (const key of TAG_KEYS) if (typeof get(frame.payload, key) === "string") tags[key] = frame.payload[key];
    return { schema: SCHEMA, spec: frame.spec, kind: frame.kind, tags, payload: shape(frame.payload) };
  }

  const schemaParticle = (value) => R.particle(value, R.SCHEMA_MAX_BYTES);

  function compareBytes(left, right) {
    for (let index = 0; index < Math.min(left.length, right.length); index++) {
      if (left[index] !== right[index]) return left[index] - right[index];
    }
    return left.length - right.length;
  }

  function validShape(value) {
    if (typeof value === "string") return TYPE_NAMES.includes(value);
    if (isObj(value)) return Object.values(value).every(validShape);
    if (Array.isArray(value)) {
      if (!value.every(validShape)) return false;
      const encoded = value.map((item) => R.canonical(item, R.SCHEMA_MAX_BYTES));
      return encoded.every((item, index) => index === 0 || compareBytes(encoded[index - 1], item) < 0);
    }
    return false;
  }

  function checkSchema(value) {
    if (!exact(value, ["schema", "spec", "kind", "tags", "payload"]) || value.schema !== SCHEMA) {
      throw new Refusal("REFUSE_SCHEMA", "A rapp-schema/1 object is exactly {schema, spec, kind, tags, payload}.");
    }
    const kind = typeof value.kind === "string" ? R.KIND_RE.exec(value.kind) : null;
    if (value.spec !== "rapp/1" || !kind || kind[1].length > 64 || kind[2].length > 64) {
      throw new Refusal("REFUSE_SCHEMA", "A rapp-schema/1 object names spec rapp/1 and a RAPP/1 kind.");
    }
    if (!isObj(value.tags) || keys(value.tags).some((key) => !TAG_KEYS.includes(key)) || Object.values(value.tags).some((item) => typeof item !== "string")) {
      throw new Refusal("REFUSE_SCHEMA", "rapp-schema/1 tags are string-valued schema, profile or operation.");
    }
    if (!isObj(value.payload) || !validShape(value.payload)) {
      throw new Refusal("REFUSE_SCHEMA", "A rapp-schema/1 payload is a shape: objects, sorted unique arrays and type names.");
    }
    return value;
  }

  function isAdditive(next, old) {
    if (next.schema !== old.schema || next.spec !== old.spec || next.kind !== old.kind || !equal(next.tags, old.tags, R.SCHEMA_MAX_BYTES)) return false;
    const oldFields = keys(old.payload), newFields = keys(next.payload);
    return oldFields.length < newFields.length && oldFields.every((key) => hasOwn(next.payload, key) && equal(next.payload[key], old.payload[key], R.SCHEMA_MAX_BYTES));
  }

  function jsonType(value) {
    return isObj(value) ? "object" : Array.isArray(value) ? "array" : shape(value);
  }

  function checkIdentifier(value, what) {
    if (!identifier(value) || value.length > 100) throw new Refusal("REFUSE_LENS", what + " must be a lowercase identifier.");
  }

  function checkVersion(value, what) {
    if (!positive(value)) throw new Refusal("REFUSE_LENS", what + " must be a positive integer.");
  }

  function checkView(view) {
    if (!exact(view, ["schema", "id", "version", "fields"]) || view.schema !== VIEW) {
      throw new Refusal("REFUSE_LENS", "A view is exactly {schema, id, version, fields}.");
    }
    checkIdentifier(view.id, "view.id");
    checkVersion(view.version, "view.version");
    if (!isObj(view.fields) || !keys(view.fields).length) throw new Refusal("REFUSE_LENS", "A view declares at least one field.");
    for (const [name, allowed] of Object.entries(view.fields)) {
      const options = Array.isArray(allowed) ? allowed : [allowed];
      if (!options.length || options.some((option) => typeof option !== "string" || !TYPES.includes(option)) || !uniqueSorted(options) || (Array.isArray(allowed) && options.length < 2)) {
        throw new Refusal("REFUSE_LENS", "view.fields." + name + " must be a type name or a sorted list of two or more.");
      }
    }
    return view;
  }

  function conforms(value, view) {
    return exact(value, keys(view.fields)) && Object.entries(view.fields).every(([name, allowed]) =>
      (Array.isArray(allowed) ? allowed : [allowed]).includes(jsonType(value[name])));
  }

  function checkExpression(expression, prefix, where) {
    if (exact(expression, ["first"])) {
      if (!Array.isArray(expression.first) || !expression.first.length) throw new Refusal("REFUSE_LENS", "'first' needs a nonempty list (at " + where + ").");
      expression.first.forEach((option, index) => checkExpression(option, prefix, where + ".first[" + index + "]"));
    } else if (exact(expression, ["select"])) {
      const path = expression.select;
      if (typeof path !== "string" || !path || path.split(".").includes("")) throw new Refusal("REFUSE_LENS", "Invalid select path at " + where + ".");
      if (prefix !== null && path !== prefix && !path.startsWith(prefix + ".")) {
        throw new Refusal("REFUSE_LENS", "Forward mappings may only select " + prefix + ".* (at " + where + ").");
      }
    } else if (exact(expression, ["const"])) {
      R.canonical(expression.const);
    } else if (isObj(expression)) {
      for (const key of keys(expression)) checkExpression(expression[key], prefix, where + "." + key);
    } else if (Array.isArray(expression)) {
      expression.forEach((value, index) => checkExpression(value, prefix, where + "[" + index + "]"));
    } else {
      throw new Refusal("REFUSE_LENS", "Lens leaves must be explicit select/const expressions (at " + where + ").");
    }
  }

  function checkLens(lens) {
    if (!exact(lens, ["schema", "id", "version", "predecessor", "view", "mappings"]) || lens.schema !== LENS) {
      throw new Refusal("REFUSE_LENS", "A lens is exactly {schema, id, version, predecessor, view, mappings}.");
    }
    checkIdentifier(lens.id, "lens.id");
    checkVersion(lens.version, "lens.version");
    const prior = lens.predecessor;
    if (lens.version === 1) {
      if (prior !== null) throw new Refusal("REFUSE_LENS", "Version 1 of a lens has no predecessor.");
    } else if (!exact(prior, ["id", "version", "particle"]) || prior.id !== lens.id || !Number.isInteger(prior.version) || prior.version !== lens.version - 1 || !hex(prior.particle)) {
      throw new Refusal("REFUSE_LENS", "A successor pins its exact predecessor {id, version, particle}.");
    }
    if (!hex(lens.view)) throw new Refusal("REFUSE_LENS", "lens.view is the particle of a view.");
    if (!Array.isArray(lens.mappings) || !lens.mappings.length) throw new Refusal("REFUSE_LENS", "A lens has at least one mapping.");
    const seen = new Set();
    lens.mappings.forEach((mapping, index) => {
      if (!exact(mapping, ["accepts", "forward", "reverse"])) throw new Refusal("REFUSE_LENS", "mappings[" + index + "] is exactly {accepts, forward, reverse}.");
      if (!Array.isArray(mapping.accepts) || !mapping.accepts.length || mapping.accepts.some((item) => !hex(item))) {
        throw new Refusal("REFUSE_LENS", "mappings[" + index + "].accepts must be a nonempty list of particles.");
      }
      if (!uniqueSorted(mapping.accepts)) throw new Refusal("REFUSE_LENS", "mappings[" + index + "].accepts must be sorted and unique.");
      if (mapping.accepts.some((item) => seen.has(item))) throw new Refusal("REFUSE_LENS", "A schema is accepted by at most one mapping of a lens.");
      mapping.accepts.forEach((item) => seen.add(item));
      checkExpression(mapping.forward, "payload", "mappings[" + index + "].forward");
      if (!isObj(mapping.forward) || keys(mapping.forward).every((key) => ["select", "const", "first"].includes(key))) {
        throw new Refusal("REFUSE_LENS", "A forward mapping builds a view object.");
      }
      if (mapping.reverse !== null) checkExpression(mapping.reverse, null, "mappings[" + index + "].reverse");
    });
    return lens;
  }

  async function reference(lens) {
    return { id: lens.id, version: lens.version, particle: await R.particle(lens) };
  }

  // JSON-encoded paths give sets Python's tuple equality, including string versus integer components.
  const newTrace = () => ({ used: new Set(), produced: new Set() });

  function select(value, path) {
    let current = value;
    for (const part of path.split(".")) {
      if (!isObj(current) || !hasOwn(current, part)) throw new LensExhaust("missing-field", path, { missing: part });
      current = current[part];
    }
    return current;
  }

  function render(expression, scope, trace = null, at = []) {
    if (exact(expression, ["first"])) {
      let last = null;
      for (const option of expression.first) {
        const attempt = trace === null ? null : newTrace();
        let value;
        try { value = render(option, scope, attempt, at); }
        catch (error) {
          if (!(error instanceof LensExhaust)) throw error;
          last = error;
          continue;
        }
        if (trace !== null) {
          for (const path of attempt.used) trace.used.add(path);
          for (const path of attempt.produced) trace.produced.add(path);
        }
        return value;
      }
      if (last !== null) throw last;
      throw new Refusal("REFUSE_LENS", "'first' needs a nonempty list.");
    }
    if (exact(expression, ["select"])) {
      const value = clone(select(scope, expression.select));
      if (trace !== null) {
        trace.used.add(JSON.stringify(expression.select.split(".")));
        trace.produced.add(JSON.stringify(at));
      }
      return value;
    }
    if (exact(expression, ["const"])) return clone(expression.const);
    if (isObj(expression)) {
      const out = dictionary();
      for (const key of keys(expression).sort()) out[key] = render(expression[key], scope, trace, at.concat(key));
      return out;
    }
    if (Array.isArray(expression)) return expression.map((value, index) => render(value, scope, trace, at.concat(index)));
    throw new Refusal("REFUSE_LENS", "Invalid lens expression.");
  }

  function mappingFor(lens, particle) {
    const index = lens.mappings.findIndex((mapping) => mapping.accepts.includes(particle));
    return index < 0 ? null : index;
  }

  async function forward(lens, index, frame, view, trace = null) {
    const value = render(lens.mappings[index].forward, { payload: frame.payload }, trace);
    if (!conforms(value, view)) throw new LensExhaust("view-shape", "forward", { view: view.id });
    return [value, await R.particle(value)];
  }

  function reverse(lens, index, value, trace = null) {
    const expression = lens.mappings[index].reverse, locus = "mappings[" + index + "].reverse";
    if (expression === null) throw new LensExhaust("no-reverse", locus);
    const payload = render(expression, value, trace);
    if (!isObj(payload)) throw new LensExhaust("no-reverse", locus, { reason: "not an object" });
    return payload;
  }

  function selects(expression) {
    if (exact(expression, ["first"])) return expression.first.flatMap(selects);
    if (exact(expression, ["select"])) return [expression.select];
    if (exact(expression, ["const"])) return [];
    if (isObj(expression)) return Object.values(expression).flatMap(selects);
    if (Array.isArray(expression)) return expression.flatMap(selects);
    return [];
  }

  function loss(lens, index, schema) {
    const paths = selects(lens.mappings[index].forward), present = keys(schema.payload);
    const referenced = new Set(paths.includes("payload") ? present : paths.filter((path) => path.startsWith("payload.")).map((path) => path.split(".")[1]));
    const matched = present.filter((key) => TAG_KEYS.includes(key) && !referenced.has(key));
    return {
      carried: sorted(present.filter((key) => referenced.has(key))),
      matched: sorted(matched),
      dropped: sorted(present.filter((key) => !referenced.has(key) && !matched.includes(key)))
    };
  }

  async function additiveSuccessor(lens, index, particle) {
    const mappings = clone(lens.mappings);
    mappings[index].accepts = sorted(Array.from(new Set(mappings[index].accepts.concat(particle))));
    return checkLens({
      schema: LENS, id: lens.id, version: lens.version + 1,
      predecessor: await reference(lens), view: lens.view, mappings
    });
  }

  const checkRappid = R.checkRappid;

  function isRappid(value) {
    try { checkRappid(value); }
    catch (error) {
      if (!(error instanceof Refusal)) throw error;
      return false;
    }
    return true;
  }

  function checkChain(frames) {
    frames.forEach((frame, index) => {
      if (frame.seq !== index || frame.stream_id !== frames[0].stream_id) throw new Refusal("REFUSE_HISTORY_ORDER", "A gap, replay or cross-stream frame was detected.");
      if (index && (frame.prev !== frames[index - 1].payload_hash || frame.utc < frames[index - 1].utc)) {
        throw new Refusal("REFUSE_HISTORY_ORDER", "A broken particle chain or UTC rollback was detected.");
      }
    });
  }

  function requireHex(value, what) {
    if (!hex(value)) throw new Refusal("REFUSE_SCHEMA", what + " must be a 64-hex particle.");
    return value;
  }

  function quorum(value, what) {
    if (!exact(value, ["quorum"]) || !positive(value.quorum)) throw new Refusal("REFUSE_SCHEMA", what + " is exactly {quorum} with a positive integer.");
  }

  function checkPolicy(policy) {
    if (!exact(policy, ["schema", "version", "predecessor", "deciders", "admit", "change_policy", "adopt_lens", "migrate_pending", "data"]) || policy.schema !== POLICY) {
      throw new Refusal("REFUSE_SCHEMA", "A policy has exactly the rapp-hive/2-policy keys.");
    }
    if (!positive(policy.version)) throw new Refusal("REFUSE_SCHEMA", "policy.version must be a positive integer.");
    if ((policy.version === 1) !== (policy.predecessor === null)) throw new Refusal("REFUSE_SCHEMA", "Only version 1 of a policy has no predecessor.");
    if (policy.predecessor !== null) requireHex(policy.predecessor, "policy.predecessor");
    const admit = policy.admit, adopt = policy.adopt_lens;
    if (!exact(admit, ["quorum", "attested"]) || !positive(admit.quorum) || typeof admit.attested !== "boolean") throw new Refusal("REFUSE_SCHEMA", "policy.admit is exactly {quorum, attested}.");
    quorum(policy.change_policy, "policy.change_policy");
    if (!exact(adopt, ["new", "additive", "successor"]) || !["automatic", "quorum"].includes(adopt.additive)) {
      throw new Refusal("REFUSE_SCHEMA", "policy.adopt_lens is exactly {new, additive, successor}.");
    }
    quorum(adopt.new, "policy.adopt_lens.new");
    quorum(adopt.successor, "policy.adopt_lens.successor");
    if (!["keep-pinned", "re-decide"].includes(policy.migrate_pending)) throw new Refusal("REFUSE_SCHEMA", "policy.migrate_pending is keep-pinned or re-decide.");
    if (!isObj(policy.data)) throw new Refusal("REFUSE_SCHEMA", "policy.data is an object.");
    if (policy.deciders !== ALL_MEMBERS) {
      if (!sortedUniqueStrings(policy.deciders)) throw new Refusal("REFUSE_SCHEMA", 'policy.deciders is "members" or a sorted, unique, nonempty list of RAPPIDs.');
      policy.deciders.forEach(checkRappid);
      if (Math.max(admit.quorum, policy.change_policy.quorum, adopt.new.quorum, adopt.successor.quorum) > policy.deciders.length) {
        throw new Refusal("REFUSE_SCHEMA", "A quorum cannot exceed the number of deciders.");
      }
    }
    return policy;
  }

  function checkAnchor(anchor) {
    if (!exact(anchor, ["schema", "name", "world_id", "founders", "policy", "legacy"]) || anchor.schema !== ANCHOR) {
      throw new Refusal("REFUSE_SCHEMA", "An anchor has exactly the rapp-hive/2-anchor keys.");
    }
    if (typeof anchor.name !== "string" || !anchor.name || textLength(anchor.name) > 100) throw new Refusal("REFUSE_SCHEMA", "anchor.name is a short text.");
    if (!identifier(anchor.world_id) || anchor.world_id.length > 64) throw new Refusal("REFUSE_SCHEMA", "anchor.world_id is a lowercase label.");
    if (!sortedUniqueStrings(anchor.founders)) {
      throw new Refusal("REFUSE_SCHEMA", "anchor.founders is a sorted, unique, nonempty list.");
    }
    anchor.founders.forEach(checkRappid);
    requireHex(anchor.policy, "anchor.policy");
    const legacy = anchor.legacy;
    if (legacy !== null) {
      if (!exact(legacy, ["from", "declaration", "join"]) || typeof legacy.from !== "string" || !legacy.from || textLength(legacy.from) > 100) throw new Refusal("REFUSE_SCHEMA", "anchor.legacy is exactly {from, declaration, join}.");
      if ((legacy.from === LEGACY_V1) !== (legacy.declaration !== null)) throw new Refusal("REFUSE_SCHEMA", "A rapp-hive/1 legacy names its declaration; other sources name none.");
      if (legacy.declaration !== null) requireHex(legacy.declaration, "anchor.legacy.declaration");
      if (legacy.join !== null) {
        const join = legacy.join;
        if (!exact(join, ["requests"]) || !sortedUniqueStrings(join.requests)) {
          throw new Refusal("REFUSE_SCHEMA", "anchor.legacy.join is exactly {requests} with sorted unique frame hashes.");
        }
        join.requests.forEach((item) => requireHex(item, "anchor.legacy.join.requests[]"));
      }
    }
    return anchor;
  }

  function portablePath(path) {
    if (typeof path !== "string" || !path || path.startsWith("/") || textLength(path) > 180 || path.normalize("NFC") !== path) {
      throw new Refusal("REFUSE_PORTABLE_PATH", "A bounded, NFC, relative POSIX path is required.");
    }
    for (const part of path.split("/")) {
      if (!part || part === "." || part === ".." || /[<>:"\\|?*\x00-\x1f\x7f]/.test(part) || /[. ]$/.test(part) ||
          /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i.test(part.split(".")[0]) || new TextEncoder().encode(part).length > 255) {
        throw new Refusal("REFUSE_PORTABLE_PATH", "A path component is not portable to every OS.");
      }
    }
  }

  async function identityKey(value) {
    if (typeof value !== "string" || !value || value.length > 1024) throw new Refusal("REFUSE_IDENTITY", "A bounded public Ed25519 SPKI is required.");
    let bytes;
    try { bytes = R.b64decode(value); }
    catch (error) {
      if (!(error instanceof Refusal)) throw error;
      throw new Refusal("REFUSE_IDENTITY", "Invalid public Ed25519 SPKI.");
    }
    if (R.b64encode(bytes) !== value) throw new Refusal("REFUSE_IDENTITY", "Only canonical base64 SPKI is supported.");
    return bytes;
  }

  async function load(files) {
    if (!isObj(files)) throw new Refusal("REFUSE_SCHEMA", "A carrier bundle is an object of paths and base64 files.");
    const paths = sorted(keys(files));
    if (paths.length > MAX_FILES) throw new Refusal("REFUSE_JSON_SIZE", "The carrier holds too many files.");
    const carried = { identities: dictionary(), objects: dictionary(), frames: [], anchor: null };
    for (const path of paths) {
      portablePath(path);
      const encoded = files[path];
      if (typeof encoded !== "string") throw new Refusal("REFUSE_UNSAFE_PATH", path + " is not a plain base64 file entry.");
      if (encoded.length > 4 * Math.ceil(R.MAX_JSON_BYTES / 3)) throw new Refusal("REFUSE_JSON_SIZE", path + " is larger than its bound.");
      const raw = R.b64decode(encoded), top = path.split("/")[0];
      if (R.b64encode(raw) !== encoded) throw new Refusal("REFUSE_ENCODING", "Noncanonical base64.");
      if (raw.length > R.MAX_JSON_BYTES) throw new Refusal("REFUSE_JSON_SIZE", path + " is larger than its bound.");
      if (!["HIVE.json", "identities", "objects", "streams"].includes(top) || !path.endsWith(".json")) continue;
      if (path === "HIVE.json") {
        const pointer = R.parseCanonical(raw);
        if (!exact(pointer, ["schema", "anchor"]) || pointer.schema !== "rapp-hive/2-carrier") throw new Refusal("REFUSE_SCHEMA", "HIVE.json is exactly {schema, anchor}.");
        carried.anchor = requireHex(pointer.anchor, "HIVE.json anchor");
      } else if (top === "identities") {
        const record = R.parseCanonical(raw);
        if (!exact(record, ["schema", "rappid", "spki_der_b64"]) || record.schema !== IDENTITY) throw new Refusal("REFUSE_IDENTITY", path + " is not a rapp-hive/2 identity record.");
        const spki = await identityKey(record.spki_der_b64);
        checkRappid(record.rappid);
        if (!await R.rappidMatches(record.rappid, spki)) throw new Refusal("REFUSE_IDENTITY", "The RAPP identity does not match its public key.");
        if (hasOwn(carried.identities, record.rappid) && carried.identities[record.rappid] !== record.spki_der_b64) {
          throw new Refusal("REFUSE_IDENTITY", "Two different keys claim one RAPPID.");
        }
        carried.identities[record.rappid] = record.spki_der_b64;
      } else if (top === "objects") {
        const value = R.parseCanonical(raw), name = path.split("/").pop().slice(0, -5);
        if (await R.particle(value, R.MAX_JSON_BYTES) !== name) throw new Refusal("REFUSE_TAMPER", path + " does not hash to its name.");
        carried.objects[name] = value;
      } else {
        carried.frames.push([path, raw]);
      }
    }
    return carried;
  }

  async function verifyFrames(carried) {
    const records = [], streams = new Map();
    for (const [path, raw] of carried.frames) {
      const frame = R.parseCanonical(raw);
      await R.frameIntegrity(frame);
      const [owner, legacy] = R.streamSigner(frame), spki = get(carried.identities, owner);
      if (spki === null) throw new Refusal("REFUSE_IDENTITY", path + ": no identity record for the signer.");
      const signature = await R.verifySignature(frame, spki, owner);
      records.push({
        frame, raw, path, owner, wave: frame.frame_hash, particle: frame.payload_hash,
        stream: frame.stream_id, seq: frame.seq, utc: frame.utc, kind: frame.kind, legacy, signature
      });
      if (!streams.has(frame.stream_id)) streams.set(frame.stream_id, []);
      streams.get(frame.stream_id).push(frame);
    }
    for (const frames of streams.values()) checkChain(frames.sort((a, b) => a.seq - b.seq));
    if (new Set(records.map((record) => record.wave)).size !== records.length) throw new Refusal("REFUSE_HISTORY_ORDER", "The same frame is carried twice.");
    carried.verification = {
      frames: records.length,
      signatures: records.filter((record) => record.signature === "verified").length,
      signature_support: await R.ed25519Available(),
      stream_ownership: true,
      whole_streams: true,
      streams: streams.size
    };
    return records.sort((a, b) => R.cmpCodePoints(a.utc, b.utc) || R.cmpCodePoints(a.wave, b.wave));
  }

  function v1Text(value, maximum = 256) {
    return typeof value === "string" && textLength(value) > 0 && textLength(value) <= maximum && value.normalize("NFC") === value;
  }

  function v1Label(value) {
    return v1Text(value, 64) && V1_LABEL_RE.test(value);
  }

  function v1Path(value) {
    if (!v1Text(value, 1024) || value.startsWith("/") || value.includes("\\") || value.includes("\x7f") || /^[A-Za-z]:/.test(value)) return false;
    return value.split("/").every((part) => !["", ".", ".."].includes(part) && !/[ .]$/.test(part) &&
      !part.includes(":") && !/[\x00-\x1f]/.test(part) &&
      !/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/.test(part.split(".", 1)[0].toUpperCase()));
  }

  function v1StringsNfc(value) {
    if (typeof value === "string") return value.normalize("NFC") === value;
    if (isObj(value)) return Object.entries(value).every(([key, item]) => key.normalize("NFC") === key && v1StringsNfc(item));
    if (Array.isArray(value)) return value.every(v1StringsNfc);
    return true;
  }

  function v1DeclarationProblem(payload) {
    if (!v1StringsNfc(payload)) return "Every string of a rapp-hive/1 declaration is NFC.";
    if (!exact(payload, V1_DECLARATION_KEYS) || payload.schema !== "rapp-hive/1-declaration") {
      return "A rapp-hive/1 declaration has exactly its nine keys and its schema.";
    }
    if (!isRappid(payload.hive_rappid) || !v1Label(payload.world_id) || !R.utcValid(payload.created_utc) || !v1Label(payload.authority_channel_id)) {
      return "hive_rappid, world_id, created_utc and authority_channel_id follow rapp-hive/1.";
    }
    const members = payload.members;
    if (!Array.isArray(members) || !members.length) return "declaration.members is a nonempty list.";
    for (const member of members) {
      if (!exact(member, ["rappid", "role", "area"]) || !isRappid(member.rappid) || typeof member.role !== "string" || !V1_ROLES.includes(member.role) || !v1Path(member.area)) {
        return "Every declared member is exactly {rappid, role, area} with an owner, member or viewer role.";
      }
    }
    const memberIds = members.map((member) => member.rappid);
    if (!uniqueSorted(memberIds) || members.filter((member) => member.role === "owner").length !== 1) {
      return "Members are unique, sorted by RAPPID, and exactly one is the owner.";
    }
    const rooms = payload.rooms, declared = new Set(memberIds);
    if (!Array.isArray(rooms) || !rooms.length) return "declaration.rooms is a nonempty list.";
    for (const room of rooms) {
      if (!exact(room, ["id", "area", "members", "access"]) || !v1Label(room.id) || !v1Path(room.area) || typeof room.access !== "string" || !V1_ROOM_ACCESS.includes(room.access)) {
        return "Every room is exactly {id, area, members, access} with repository or sealed access.";
      }
      const audience = room.members;
      if (!Array.isArray(audience) || !audience.length || !audience.every(isRappid) || !uniqueSorted(audience) || !audience.every((member) => declared.has(member))) {
        return "A room's members are a nonempty, sorted, unique list of declared members.";
      }
    }
    if (!uniqueSorted(rooms.map((room) => room.id))) return "Rooms are unique and sorted by id.";
    const channels = payload.channels;
    if (!Array.isArray(channels) || !channels.length) return "declaration.channels is a nonempty list.";
    const authorities = [];
    for (const channel of channels) {
      if (!exact(channel, ["id", "kind", "role", "locator", "writeback"]) || !v1Label(channel.id) ||
          typeof channel.kind !== "string" || !V1_CHANNEL_KINDS.includes(channel.kind) ||
          typeof channel.role !== "string" || !V1_CHANNEL_ROLES.includes(channel.role) ||
          !v1Text(channel.locator, 2048) || typeof channel.writeback !== "boolean") {
        return "Every channel is exactly {id, kind, role, locator, writeback} with a supported kind and role.";
      }
      if (channel.role === "authority") {
        if (!channel.writeback) return "The authority channel supports writeback.";
        authorities.push(channel.id);
      }
    }
    if (!uniqueSorted(channels.map((channel) => channel.id)) || authorities.length !== 1 || authorities[0] !== payload.authority_channel_id) {
      return "Channels are unique and sorted by id, with exactly the one named authority channel.";
    }
    const policy = payload.policy;
    if (!exact(policy, keys(V1_PRIVACY)) || Object.entries(V1_PRIVACY).some(([key, value]) => policy[key] !== value || typeof policy[key] !== "string")) {
      return "The rapp-hive/1 privacy policy has its fixed values.";
    }
    return null;
  }

  function checkLegacyDeclaration(record) {
    const payload = record.frame.payload;
    if (record.kind !== "hive.declaration") throw new Refusal("REFUSE_LEGACY", "The legacy declaration is not a hive.declaration frame.");
    const problem = v1DeclarationProblem(payload);
    if (problem !== null) throw new Refusal("REFUSE_LEGACY", "Not a declaration rapp-hive/1 accepts: " + problem);
    const roles = { owner: [], member: [], viewer: [] };
    for (const item of payload.members) roles[item.role].push(item.rappid);
    if (!record.legacy || record.stream !== get(payload, "hive_rappid") || record.seq !== 0) {
      throw new Refusal("REFUSE_LEGACY", "A rapp-hive/1 declaration is the genesis of its Mother Hive stream (stream_id = hive_rappid).");
    }
    if (record.owner !== roles.owner[0]) throw new Refusal("REFUSE_LEGACY", "A rapp-hive/1 declaration is signed by its declared owner.");
    return {
      owner: roles.owner[0], members: sorted(Array.from(new Set(roles.member))), viewers: sorted(Array.from(new Set(roles.viewer))),
      world_id: payload.world_id, privacy: payload.policy
    };
  }

  function governanceProblem(kind, payload) {
    const [name, names] = KINDS[kind];
    if (!exact(payload, names) || get(payload, "schema") !== name) return kind + " payload is not " + name + ".";
    if (!hex(payload.anchor)) return "anchor is a 64-hex particle.";
    if (kind === "hive2.join" && !hex(payload.policy)) return "A join pins a policy particle.";
    if (kind === "hive2.grant" && (!isRappid(payload.member) || !hex(payload.request))) return "A grant names a member RAPPID and a request frame hash.";
    if (kind === "hive2.adopt" && (!hex(payload.object) || !(payload.predecessor === null || hex(payload.predecessor)))) {
      return "An adoption names an object particle and a predecessor particle or null.";
    }
    if (kind === "hive2.attest") {
      if (!isRappid(payload.subject)) return "An attestation names a keyed RAPPID.";
      if (typeof payload.claim !== "string" || typeof payload.method !== "string" || !payload.claim || !payload.method || textLength(payload.claim) > 100 || textLength(payload.method) > 200) {
        return "An attestation has a short claim and method.";
      }
    }
    return null;
  }

  class Evaluation {
    constructor(carried, records, anchor, membersOnly = false) {
      this.carried = carried;
      this.anchor_particle = anchor;
      this.members_only = membersOnly;
      this.final_members = new Set();
      if (!hasOwn(carried.objects, anchor)) throw new Refusal("REFUSE_ANCHOR", "The anchor object is not carried.");
      this.anchor = checkAnchor(carried.objects[anchor]);
      if (this._policy(this.anchor.policy).version !== 1) throw new Refusal("REFUSE_ANCHOR", "The anchor pins a version 1 policy.");
      this.policy_chain = [this.anchor.policy];
      for (const name of ["members", "pending", "attested", "active", "lens_objects", "schemas", "frame_schema"]) this[name] = dictionary();
      for (const name of ["attestations", "derived", "history", "refusals", "events", "content", "quarantine", "manifests", "other_hives"]) this[name] = [];
      this.tallies = new Map();
      for (const [particle, value] of Object.entries(carried.objects)) if (isObj(value) && value.schema === SCHEMA) this.schemas[particle] = checkSchema(value);
      this.records = records;
      const legacy = this.anchor.legacy;
      this.legacy_joins = new Set(legacy && legacy.join ? legacy.join.requests : []);
      this.legacy_declaration = legacy ? legacy.declaration : null;
      this._check_legacy(records);
    }

    static async create(carried, records, anchor, membersOnly = false) {
      // The first pass shares only its final member set, never its tallies or refusals.
      const membership = membersOnly ? null : await Evaluation.create(carried, records, anchor, true);
      const evaluation = new Evaluation(carried, records, anchor, membersOnly);
      if (membership !== null) evaluation.final_members = new Set(keys(membership.members));
      for (const record of records) await evaluation._process(record);
      if (!membersOnly) await evaluation._finish();
      return evaluation;
    }

    _policy(particle) {
      if (!hasOwn(this.carried.objects, particle)) throw new Refusal("REFUSE_POLICY", "A referenced policy is not carried.");
      return checkPolicy(this.carried.objects[particle]);
    }

    get policy() { return this._policy(this.policy_chain[this.policy_chain.length - 1]); }
    _refuse(record, code, reason) { this.refusals.push({ wave: record.wave, code, reason }); }
    _event(record, event) { this.events.push({ utc: record.utc, wave: record.wave, event }); }

    _check_legacy(records) {
      const byWave = new Map(records.map((record) => [record.wave, record]));
      if (this.legacy_declaration !== null) {
        const declaration = byWave.get(this.legacy_declaration);
        if (!declaration) throw new Refusal("REFUSE_LEGACY", "The legacy declaration named by the anchor is not carried.");
        const declared = checkLegacyDeclaration(declaration);
        if (declared.world_id !== this.anchor.world_id || !this.anchor.founders.every((founder) => founder === declared.owner || declared.members.includes(founder))) {
          throw new Refusal("REFUSE_LEGACY", "Founders and world must come from the legacy declaration.");
        }
      }
      for (const wave of this.legacy_joins) {
        const request = byWave.get(wave);
        if (!request) throw new Refusal("REFUSE_LEGACY", "A grandfathered legacy request is not carried.");
        if (hasOwn(KINDS, request.kind) || wave === this.legacy_declaration) throw new Refusal("REFUSE_LEGACY", "A grandfathered request is a signed content frame of its requester.");
      }
    }

    _decides(policy, who) {
      return hasOwn(this.members, who) && (policy.deciders === ALL_MEMBERS || policy.deciders.includes(who));
    }

    _try_admit(key) {
      const request = get(this.pending, key);
      if (request === null) return;
      if (hasOwn(this.members, request.requester)) {
        delete this.pending[key];
        this.events.push({ utc: null, wave: key, event: "request closed: already a member" });
        return;
      }
      const pinned = this._policy(request.pinned), rule = pinned.admit;
      const grants = Array.from(request.grants).filter((member) => this._decides(pinned, member));
      const vouched = Array.from(get(this.attested, request.requester, new Set())).filter((member) => hasOwn(this.members, member) && member !== request.requester);
      if (grants.length >= rule.quorum && (!rule.attested || vouched.length)) {
        this.members[request.requester] = { how: "admitted", request: key, under: request.pinned, legacy: request.legacy, grants: sorted(grants) };
        delete this.pending[key];
        this.events.push({ utc: null, wave: key, event: "admitted" });
        for (const other of sorted(keys(this.pending))) {
          if (get(this.pending, other, {}).requester === request.requester) this._try_admit(other);
        }
      }
    }

    async _schema(record) {
      if (!hasOwn(this.frame_schema, record.wave)) {
        const value = schemaOf(record.frame), particle = await schemaParticle(value);
        if (!hasOwn(this.schemas, particle)) this.schemas[particle] = value;
        this.frame_schema[record.wave] = particle;
      }
      return this.frame_schema[record.wave];
    }

    _view(lens) {
      const view = get(this.carried.objects, lens.view);
      if (view === null) throw new Refusal("REFUSE_LENS", "A lens names a view that is not carried.");
      return checkView(view);
    }

    _mappers(particle) {
      const found = [];
      for (const id of sorted(keys(this.active))) {
        const index = mappingFor(this.lens_objects[this.active[id]], particle);
        if (index !== null) found.push([id, index]);
      }
      return found;
    }

    async _process(record) {
      const payload = record.frame.payload;
      if (hasOwn(KINDS, record.kind)) {
        if (record.legacy) return this._refuse(record, "REFUSE_LEGACY_STREAM", "Governance is signed on the signer's own memory stream, never on a body stream.");
        if (record.kind === "hive2.manifest") {
          if (get(payload, "anchor") === this.anchor_particle) this.manifests.push(record);
          return;
        }
        const problem = governanceProblem(record.kind, payload);
        if (problem !== null) return this._refuse(record, "REFUSE_GOVERNANCE_SHAPE", problem);
        if (payload.anchor !== this.anchor_particle) { this.other_hives.push(record.wave); return; }
        await this["_" + record.kind.split(".")[1]](record, payload);
        return;
      }
      if (record.wave === this.legacy_declaration) return;
      if (this.legacy_joins.has(record.wave)) {
        this.pending[record.wave] = { requester: record.owner, pinned: this.anchor.policy, grants: new Set(), legacy: true };
        this._event(record, "legacy request carried over (pinned to the first policy)");
        this._try_admit(record.wave);
        return;
      }
      if (this.members_only) return;
      if (!this.final_members.has(record.owner)) {
        this.quarantine.push(record);
        return;
      }
      this.content.push(record);
      await this._route(record);
    }

    _accept(record) {
      if (!this.anchor.founders.includes(record.owner)) return this._refuse(record, "REFUSE_NOT_FOUNDER", "Only a founder can accept the anchor.");
      if (!hasOwn(this.members, record.owner)) {
        this.members[record.owner] = { how: "founder" };
        this._event(record, "founder accepted the anchor");
        for (const key of sorted(keys(this.pending))) if (get(this.pending, key, {}).requester === record.owner) this._try_admit(key);
      }
    }

    _join(record, payload) {
      if (hasOwn(this.members, record.owner)) return this._refuse(record, "REFUSE_ALREADY_MEMBER", "Members do not join again.");
      if (payload.policy !== this.policy_chain[this.policy_chain.length - 1]) return this._refuse(record, "REFUSE_STALE", "A request pins the policy active when it is made.");
      if (Object.values(this.pending).some((item) => item.requester === record.owner)) return this._refuse(record, "REFUSE_DUPLICATE", "This identity already has a pending request.");
      this.pending[record.wave] = { requester: record.owner, pinned: payload.policy, grants: new Set(), legacy: false };
      this._event(record, "requested to join");
      this._try_admit(record.wave);
    }

    _grant(record, payload) {
      if (!hasOwn(this.members, record.owner)) return this._refuse(record, "REFUSE_NOT_MEMBER", "Only members grant.");
      const request = get(this.pending, payload.request);
      if (request === null || request.requester !== payload.member) return this._refuse(record, "REFUSE_UNKNOWN_REQUEST", "The grant names no pending request of that identity.");
      if (!this._decides(this._policy(request.pinned), record.owner)) {
        return this._refuse(record, "REFUSE_NOT_DECIDER", "The policy this request is decided under does not let this member decide.");
      }
      request.grants.add(record.owner);
      this._event(record, "granted a pending request");
      this._try_admit(payload.request);
    }

    _attest(record, payload) {
      if (!hasOwn(this.members, record.owner)) return this._refuse(record, "REFUSE_NOT_MEMBER", "Only members attest.");
      this.attestations.push({ by: record.owner, subject: payload.subject, claim: payload.claim, method: payload.method, wave: record.wave });
      if (payload.claim === "key-confirmed" && payload.subject !== record.owner) {
        if (!hasOwn(this.attested, payload.subject)) this.attested[payload.subject] = new Set();
        this.attested[payload.subject].add(record.owner);
      }
      for (const key of sorted(keys(this.pending))) if (get(this.pending, key, {}).requester === payload.subject) this._try_admit(key);
    }

    async _adopt(record, payload) {
      if (!hasOwn(this.members, record.owner)) return this._refuse(record, "REFUSE_NOT_MEMBER", "Only members adopt.");
      const target = payload.object;
      let value = get(this.carried.objects, target);
      if (value === null || value === false || value === 0 || value === "" || (isObj(value) && !keys(value).length) || (Array.isArray(value) && !value.length)) value = get(this.lens_objects, target);
      if (!isObj(value)) return this._refuse(record, "REFUSE_UNKNOWN_OBJECT", "The adopted object is not carried.");
      try {
        if (value.schema === POLICY) return this._adopt_policy(record, payload, target, checkPolicy(value));
        if (value.schema === LENS) {
          if (this.members_only) return;
          return await this._adopt_lens(record, payload, target, checkLens(value));
        }
      } catch (error) {
        if (!(error instanceof Refusal)) throw error;
        return this._refuse(record, error.code, error.message);
      }
      this._refuse(record, "REFUSE_UNKNOWN_OBJECT", "Only policies and lenses are adopted.");
    }

    _tally(kind, target, owner, policy) {
      const key = kind + ":" + target;
      if (!this.tallies.has(key)) this.tallies.set(key, new Set());
      const tally = this.tallies.get(key);
      tally.add(owner);
      return Array.from(tally).filter((member) => this._decides(policy, member)).length;
    }

    _adopt_policy(record, payload, target, value) {
      const current = this.policy_chain[this.policy_chain.length - 1], active = this.policy;
      if (payload.predecessor !== current || value.predecessor !== current || value.version !== active.version + 1) {
        return this._refuse(record, "REFUSE_STALE", "A policy successor pins the active policy (compare-and-swap).");
      }
      if (!this._decides(active, record.owner)) return this._refuse(record, "REFUSE_NOT_DECIDER", "The active policy does not let this member decide.");
      const count = this._tally("policy", target, record.owner, active);
      this._event(record, "adopted policy v" + value.version);
      if (count >= active.change_policy.quorum) {
        this.policy_chain.push(target);
        this._event(record, "policy v" + value.version + " is active");
        if (value.migrate_pending === "re-decide") for (const request of Object.values(this.pending)) request.pinned = target;
        for (const key of sorted(keys(this.pending))) this._try_admit(key);
      }
    }

    async _adopt_lens(record, payload, target, value) {
      this._view(value);
      const current = get(this.active, value.id);
      let needed;
      if (payload.predecessor === null) {
        if (current !== null || value.predecessor !== null) return this._refuse(record, "REFUSE_STALE", "This lens id is active already; adopt a successor.");
        needed = this.policy.adopt_lens.new.quorum;
      } else {
        if (current === null || payload.predecessor !== current || value.predecessor === null || !equal(value.predecessor, await reference(this.lens_objects[current]))) {
          return this._refuse(record, "REFUSE_STALE", "A lens successor pins the active version exactly (compare-and-swap).");
        }
        needed = this.policy.adopt_lens.successor.quorum;
      }
      const active = this.policy;
      if (!this._decides(active, record.owner)) return this._refuse(record, "REFUSE_NOT_DECIDER", "The active policy does not let this member decide.");
      if (!hasOwn(this.lens_objects, target)) this.lens_objects[target] = value;
      const count = this._tally("lens", target, record.owner, active);
      this._event(record, "adopted lens " + value.id + " v" + value.version);
      if (count >= needed) {
        if (current !== null) {
          const broken = await this._laws(value, this.lens_objects[current]);
          if (broken) return this._refuse(record, "REFUSE_LENS_LAW", broken);
        }
        this.active[value.id] = target;
        this.history.push(target);
        this._event(record, "lens " + value.id + " v" + value.version + " is active");
      }
    }

    async _laws(candidate, predecessor) {
      if (candidate.view !== predecessor.view) return "A successor keeps its predecessor's view (a new view is a new lens id).";
      const accepted = new Set(candidate.mappings.flatMap((mapping) => mapping.accepts));
      if (predecessor.mappings.some((mapping) => mapping.accepts.some((particle) => !accepted.has(particle)))) return "A successor accepts every schema its predecessor accepted.";
      const view = this._view(predecessor);
      for (const record of this.content) {
        const particle = await this._schema(record), oldIndex = mappingFor(predecessor, particle);
        if (oldIndex === null) continue;
        let old;
        try { old = (await forward(predecessor, oldIndex, record.frame, view))[1]; }
        catch (error) { if (!(error instanceof LensExhaust)) throw error; continue; }
        const newIndex = mappingFor(candidate, particle);
        let next = null;
        try { if (newIndex !== null) next = (await forward(candidate, newIndex, record.frame, view))[1]; }
        catch (error) { if (!(error instanceof LensExhaust)) throw error; }
        if (next !== old) return "The successor changes what an existing message means (" + record.wave.slice(0, 12) + ").";
      }
      return null;
    }

    async _route(record) {
      const particle = await this._schema(record);
      if (this._mappers(particle).length) return;
      const candidates = new Map(), newSchema = this.schemas[particle];
      for (const id of sorted(keys(this.active))) {
        const lens = this.lens_objects[this.active[id]];
        for (let index = 0; index < lens.mappings.length; index++) {
          if (!lens.mappings[index].accepts.some((old) => hasOwn(this.schemas, old) && isAdditive(newSchema, this.schemas[old]))) continue;
          try { await forward(lens, index, record.frame, this._view(lens)); }
          catch (error) { if (!(error instanceof LensExhaust)) throw error; continue; }
          if (!candidates.has(id)) candidates.set(id, []);
          candidates.get(id).push(index);
        }
      }
      if (candidates.size !== 1) return;
      const [id, indexes] = candidates.entries().next().value;
      if (indexes.length !== 1) return;
      const successor = await additiveSuccessor(this.lens_objects[this.active[id]], indexes[0], particle);
      const target = await R.particle(successor);
      if (!hasOwn(this.lens_objects, target)) this.lens_objects[target] = successor;
      this.derived.push(target);
      if (this.policy.adopt_lens.additive === "automatic") {
        this.active[id] = target;
        this.history.push(target);
        this._event(record, "new fields only: lens " + id + " v" + successor.version + " learned automatically");
      }
    }

    async _finish() {
      this.views = [];
      const waiting = new Map();
      this.quarantined = this.quarantine.map((record) => record.wave);
      for (const record of this.content) {
        const particle = await this._schema(record), mappers = this._mappers(particle);
        let code, detail;
        if (mappers.length === 1) {
          const [id, index] = mappers[0], lens = this.lens_objects[this.active[id]];
          try {
            const [value, viewParticle] = await forward(lens, index, record.frame, this._view(lens));
            this.views.push({ source: record.wave, owner: record.owner, schema: particle, lens: await reference(lens), view: viewParticle, value });
            continue;
          } catch (error) {
            if (!(error instanceof LensExhaust)) throw error;
            code = error.code;
            detail = error.detail;
          }
        } else {
          code = mappers.length ? "ambiguous" : "no-lens";
          detail = mappers.length ? { lenses: mappers.map((item) => item[0]) } : {};
        }
        if (!waiting.has(particle)) waiting.set(particle, { schema: particle, code, detail, waiting: [] });
        waiting.get(particle).waiting.push(record.wave);
      }
      this.exhausts = sorted(Array.from(waiting.keys())).map((key) => waiting.get(key));
      const lenses = dictionary();
      for (const id of sorted(keys(this.active))) lenses[id] = this.active[id];
      this.state = {
        schema: STATE, anchor: this.anchor_particle, policy: this.policy_chain[this.policy_chain.length - 1],
        members: sorted(keys(this.members)), lenses, pending: sorted(keys(this.pending))
      };
      this.state_particle = await R.particle(this.state);
    }
  }

  function atHeads(records, heads) {
    const byPosition = new Map(records.map((record) => [JSON.stringify([record.stream, record.seq]), record]));
    for (const [stream, head] of Object.entries(heads)) {
      if (!exact(head, ["seq", "frame_hash"]) || !Number.isInteger(head.seq) || typeof head.frame_hash !== "string") {
        throw new Refusal("REFUSE_MANIFEST", "A manifest head is exactly {seq, frame_hash}.");
      }
      const found = byPosition.get(JSON.stringify([stream, head.seq]));
      if (!found || found.wave !== head.frame_hash) throw new Refusal("REFUSE_MANIFEST", "A manifest head names a frame this carrier does not hold.");
      if (found.kind === "hive2.manifest") throw new Refusal("REFUSE_MANIFEST", "Manifest heads exclude manifests.");
    }
    return records.filter((record) => hasOwn(heads, record.stream) && record.seq <= heads[record.stream].seq && record.kind !== "hive2.manifest");
  }

  async function manifests(carried, records, evaluation) {
    const carrierHeads = dictionary(), latest = dictionary();
    for (const record of records) {
      if (record.kind !== "hive2.manifest" && (!hasOwn(carrierHeads, record.stream) || record.seq > carrierHeads[record.stream].seq)) {
        carrierHeads[record.stream] = { seq: record.seq, frame_hash: record.wave };
      }
    }
    for (const record of evaluation.manifests) {
      if (hasOwn(evaluation.members, record.owner)) latest[record.owner] = record;
    }
    const results = [];
    for (const owner of sorted(keys(latest))) {
      const record = latest[owner], payload = record.frame.payload;
      if (!exact(payload, KINDS["hive2.manifest"][1]) || payload.schema !== KINDS["hive2.manifest"][0] || !isObj(payload.heads) || !hex(payload.state)) {
        results.push({ wave: record.wave, by: owner, verdict: "malformed" });
        continue;
      }
      let recomputed;
      try { recomputed = (await Evaluation.create(carried, atHeads(records, payload.heads), evaluation.anchor_particle)).state_particle; }
      catch (error) {
        if (!(error instanceof Refusal)) throw error;
        results.push({ wave: record.wave, by: owner, verdict: "unverifiable", code: error.code });
        continue;
      }
      results.push({
        wave: record.wave, by: owner, verdict: recomputed === payload.state ? "consistent" : "divergent",
        position: equal(payload.heads, carrierHeads) ? "agrees" : "behind",
        state: payload.state, same_state: payload.state === evaluation.state_particle,
        missing_frames: keys(carrierHeads).reduce((sum, stream) => sum + carrierHeads[stream].seq - get(payload.heads, stream, { seq: -1 }).seq, 0)
      });
    }
    return results;
  }

  function verdict(evaluation, manifestResults) {
    return {
      schema: VERDICT, state: evaluation.state, state_particle: evaluation.state_particle,
      views: evaluation.views.map((item) => ({ source: item.source, schema: item.schema, lens: item.lens.particle, view: item.view })),
      exhausts: evaluation.exhausts.map((item) => ({ schema: item.schema, code: item.code, waiting: item.waiting })),
      refusals: evaluation.refusals.map((item) => ({ wave: item.wave, code: item.code })),
      quarantined: evaluation.quarantined, derived_lenses: evaluation.derived,
      manifests: manifestResults.map((item) => ({ wave: item.wave, verdict: item.verdict, position: get(item, "position") }))
    };
  }

  async function evaluate(files, anchor = null) {
    const carried = await load(files), records = await verifyFrames(carried);
    const chosen = anchor || carried.anchor;
    if (chosen === null) throw new Refusal("REFUSE_ANCHOR", "Name the anchor (HIVE.json or an explicit anchor).");
    const evaluation = await Evaluation.create(carried, records, chosen);
    const manifestResults = await manifests(carried, records, evaluation);
    return { carried, records, evaluation, manifests: manifestResults, verdict: verdict(evaluation, manifestResults), verification: carried.verification };
  }

  function leaves(value, at) {
    let node = value;
    for (const part of at) node = node[part];
    if (isObj(node) && keys(node).length) return keys(node).flatMap((key) => leaves(value, at.concat(key)));
    return [at];
  }

  function covered(leaf, used) {
    return used.some((path) => path.length <= leaf.length && path.every((part, offset) => part === leaf[offset]));
  }

  function droppedFields(payload, used) {
    const paths = Array.from(used).map((path) => JSON.parse(path));
    const sourceLeaves = keys(payload).filter((key) => !(TAG_KEYS.includes(key) && typeof payload[key] === "string"))
      .flatMap((key) => leaves(payload, [key]));
    return sorted(sourceLeaves.filter((leaf) => !covered(["payload", ...leaf], paths)).map((leaf) => leaf.map(String).join(".")));
  }

  async function cross(evaluation, sourceWave, targetSchema) {
    const entry = evaluation.views.find((item) => item.source === sourceWave);
    if (!entry) throw new Refusal("REFUSE_CROSSING", "Only a mapped message of a member can cross.");
    const record = evaluation.content.find((item) => item.wave === sourceWave), sourceLens = evaluation.lens_objects[entry.lens.particle];
    const index = mappingFor(sourceLens, entry.schema), trace = newTrace();
    const [value, viewParticle] = await forward(sourceLens, index, record.frame, evaluation._view(sourceLens), trace);
    const target = get(evaluation.schemas, targetSchema);
    if (target === null) throw new Refusal("REFUSE_CROSSING", "The target schema is not known to this Hive.");
    const fits = new Map();
    const history = evaluation.history.slice().sort((a, b) => {
      const left = evaluation.lens_objects[a], right = evaluation.lens_objects[b];
      return R.cmpCodePoints(left.id, right.id) || right.version - left.version;
    });
    for (const particle of history) {
      const candidate = evaluation.lens_objects[particle];
      if (fits.has(candidate.id) || candidate.view !== sourceLens.view) continue;
      const targetIndex = mappingFor(candidate, targetSchema);
      if (targetIndex === null) continue;
      const backward = newTrace();
      let payload;
      try { payload = reverse(candidate, targetIndex, value, backward); }
      catch (error) { if (!(error instanceof LensExhaust)) throw error; continue; }
      if (await schemaParticle(schemaOf({ spec: target.spec, kind: target.kind, payload })) === targetSchema) {
        fits.set(candidate.id, { candidate, payload, backward });
      }
    }
    if (fits.size > 1) throw new Refusal("REFUSE_LENS_COLLISION", "More than one lens can express this message in the target schema; refusing to guess.");
    if (!fits.size) throw new Refusal("REFUSE_CROSSING", "No lens version expresses this message in the target schema exactly; the Hive will not invent missing fields.");
    const { candidate, payload, backward } = fits.values().next().value;
    const produced = new Set(Array.from(trace.produced).flatMap((path) => leaves(value, JSON.parse(path))).map((path) => JSON.stringify(path)));
    const used = Array.from(backward.used).map((path) => JSON.parse(path));
    const missing = sorted(Array.from(produced).map((path) => JSON.parse(path))
      .filter((leaf) => !covered(leaf, used))
      .map((path) => path.map(String).join(".")));
    const dropped = droppedFields(record.frame.payload, trace.used);
    return {
      schema: "rapp-hive/2-crossing", authority: false, signed: false,
      from: { source: sourceWave, owner: record.owner, schema: entry.schema }, to_schema: targetSchema,
      through: { forward: await reference(sourceLens), view: viewParticle, reverse: await reference(candidate) },
      payload, payload_particle: await R.particle(payload), dropped_by_forward_lens: dropped,
      not_expressible_in_target: missing, lossless: !dropped.length && !missing.length,
      note: "An unsigned proposal in the target schema; only the receiving owner can sign it."
    };
  }

  async function crossToMember(evaluation, source, member) {
    if (typeof source !== "string") throw new Refusal("REFUSE_UNKNOWN_TARGET", "Name the message by at least 8 hex characters.");
    const needle = source.trim().toLowerCase();
    if (needle.length < 8) throw new Refusal("REFUSE_UNKNOWN_TARGET", "Name the message by at least 8 hex characters.");
    const found = [...evaluation.content, ...evaluation.quarantine].filter((item) => item.wave.startsWith(needle) || item.particle.startsWith(needle));
    if (found.length !== 1) throw new Refusal("REFUSE_UNKNOWN_TARGET", "That names no carried message, or more than one.");
    const owners = keys(evaluation.members).filter((rappid) => rappid === member || rappid.split("/")[1].split(":")[0] === member);
    if (owners.length !== 1) throw new Refusal("REFUSE_UNKNOWN_TARGET", "Name the receiving member by RAPPID or slug.");
    const targets = [];
    for (const record of evaluation.content.slice().reverse()) {
      if (record.owner !== owners[0]) continue;
      const particle = await evaluation._schema(record);
      if (!targets.includes(particle)) targets.push(particle);
    }
    let last = null;
    for (const target of targets) {
      try { return await cross(evaluation, found[0].wave, target); }
      catch (error) { if (!(error instanceof Refusal)) throw error; last = error; }
    }
    throw last || new Refusal("REFUSE_CROSSING", "The receiving member has written nothing to cross into.");
  }

  root.RAPPHIVE2 = {
    schema: { VERSION: SCHEMA, TAG_KEYS, shape, schema_of: schemaOf, particle: schemaParticle, check_schema: checkSchema, is_additive: isAdditive },
    lens: {
      VIEW, LENS, LensExhaust, check_view: checkView, check_lens: checkLens, conforms, json_type: jsonType,
      reference, new_trace: newTrace, render, mapping_for: mappingFor, forward, reverse, loss, additive_successor: additiveSuccessor
    },
    ANCHOR, POLICY, IDENTITY, STATE, VERDICT, KINDS, MAX_FILES, ALL_MEMBERS, LEGACY_V1,
    check_rappid: checkRappid, stream_signer: R.streamSigner, check_chain: checkChain,
    check_policy: checkPolicy, check_anchor: checkAnchor, load, verify_frames: verifyFrames,
    v1_declaration_problem: v1DeclarationProblem, check_legacy_declaration: checkLegacyDeclaration, governance_problem: governanceProblem,
    Evaluation, manifests, verdict, evaluate, cross, cross_to_member: crossToMember, dropped_fields: droppedFields
  };
})(globalThis);
