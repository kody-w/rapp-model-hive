(function () {
  "use strict";

  const R = globalThis.RAPP1, H = globalThis.RAPPHIVE2;
  const MAX_BUNDLE_BYTES = 8 * 1024 * 1024;
  let story, lessons, trust, originalFiles, before, current, main, live;
  let busy = false;
  const notes = new Map(), downloads = new Set();

  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }
  const paragraph = (text, className) => element("p", text, className);
  const short = (value) => value.slice(0, 12) + "...";
  const full = (result) => result.verification.signature_support && result.verification.signatures === result.verification.frames;
  const code = (text) => element("code", text);

  function block(id, limit = R.MAX_JSON_BYTES) {
    const source = document.getElementById(id);
    if (!source) throw new Error("The page is missing its " + id + " data block.");
    return R.parseCanonical(R.b64decode(source.textContent), limit);
  }

  function person(rappid) {
    const label = R.own(R.own(story.people, rappid), "label");
    return typeof label === "string" ? label : rappid.split("/").pop().split(":")[0];
  }
  const firstName = (rappid) => person(rappid).split(" (")[0];
  const whoDecides = (policy) => policy.deciders === H.ALL_MEMBERS ? "Every member" : policy.deciders.map(firstName).join(", ");
  const titleOf = (record) => {
    const payload = record.frame.payload;
    for (const field of ["title", "summary", "text"]) if (typeof R.own(payload, field) === "string") return payload[field];
    return typeof payload.operation === "string" ? payload.operation + " message" : record.kind;
  };

  function status(text) { live.textContent = text; }

  function refusalText(error) {
    const explanations = {
      REFUSE_FRAME_HASH: "A message changed, but its fingerprint did not. The signed record no longer matches.",
      REFUSE_TAMPER: "A carried object no longer matches the fingerprint in its file name.",
      REFUSE_SIGNATURE: "A signature does not match its signer's key, or a memory stream is signed by someone other than its owner.",
      REFUSE_FRAME_TIME: "A signed step has an impossible date or time, or does not use the required UTC format.",
      REFUSE_FRAME_SHAPE: "A signed step does not follow the required frame format, kind, stream name or wire-chain rules.",
      REFUSE_SCHEMA: "A carried shape description is not one the protocol could produce, or its anchor or policy fields are invalid. This copy is refused.",
      REFUSE_HISTORY_ORDER: "A stream has a missing, repeated, out-of-order or broken step.",
      REFUSE_IDENTITY: "A signing identity is missing, or its key does not match its identity.",
      REFUSE_ANCHOR: "This tour accepts only copies of its pinned model Hive. Its starting identity must match.",
      REFUSE_CANONICAL_JSON: "The JSON bytes are not in the exact format this carrier requires. Use an unchanged exported bundle.",
      REFUSE_JSON_SIZE: "The bundle is empty or too large. Bundles are limited to 8 MiB; each carried file to 1 MiB.",
      REFUSE_ENCODING: "A carried file is not valid, bounded base64. Base64 is the text wrapping around its original bytes.",
      REFUSE_PORTABLE_PATH: "A file name is unsafe or cannot travel between supported devices.",
      REFUSE_UNSAFE_PATH: "The carrier contains something other than a plain file or folder, such as a link or special entry.",
      REFUSE_LEGACY: "The old declaration or request is missing, not signed by the declared owner, or not what rapp-hive/1 accepts.",
      REFUSE_NOT_DECIDER: "This member is not allowed to decide under the rules governing this request or change. The approval has no effect.",
      REFUSE_LEGACY_STREAM: "A body stream can carry old content, not new Hive decisions. Decisions must be signed on the signer's own memory stream.",
      REFUSE_GOVERNANCE_SHAPE: "This request does not contain the exact fields and valid references the Hive's decision rules require. It has no effect.",
      REFUSE_MANIFEST: "The device's list of newest steps is malformed, names a step this copy does not hold, or incorrectly lists another manifest. Its claim cannot be checked.",
      REFUSE_LENS_COLLISION: "More than one translation fits. The Hive refuses to guess.",
      REFUSE_CROSSING: "No available translation can rebuild the receiving app's shape exactly. The Hive will not invent missing fields."
    };
    return R.own(explanations, error.code) || error.message;
  }

  function showRefusal(target, heading, error, after) {
    const card = element("div", null, "result danger");
    card.dataset.outcome = "refused";
    card.append(element("h3", heading), paragraph(refusalText(error)), code(error.code));
    if (after) card.append(paragraph(after, "muted"));
    target.replaceChildren(card);
  }

  async function action(message, work) {
    if (busy) return;
    busy = true;
    const controls = Array.from(main.querySelectorAll("button, input, select"), (node) => [node, node.disabled]);
    controls.forEach(([node]) => { node.disabled = true; });
    status(message);
    try { await work(); }
    catch (error) {
      status("Could not finish: " + (error instanceof R.Refusal ? error.code + ". " + refusalText(error) : error.message || String(error)));
      if (!(error instanceof R.Refusal)) console.error(error);
    } finally {
      busy = false;
      controls.forEach(([node, disabled]) => { if (node.isConnected) node.disabled = disabled; });
    }
  }

  function button(text, id, handler, secondary = false) {
    const node = element("button", text, secondary ? "secondary" : "");
    node.type = "button";
    node.id = id;
    node.addEventListener("click", handler);
    return node;
  }

  function field(label, node) {
    const wrap = element("div"), caption = element("label", label);
    caption.htmlFor = node.id;
    wrap.append(caption, node);
    return wrap;
  }

  function select(id, options) {
    const node = element("select");
    node.id = id;
    for (const [value, label] of options) {
      const option = element("option", label);
      option.value = value;
      node.append(option);
    }
    if (!options.length) {
      node.append(element("option", "No messages in this copy"));
      node.disabled = true;
    }
    return node;
  }

  function table(caption, headings, rows, className = "") {
    const wrap = element("div", null, "table-wrap"), grid = element("table", null, className);
    wrap.tabIndex = 0;
    wrap.setAttribute("role", "region");
    wrap.setAttribute("aria-label", caption + " (scroll sideways on a small screen)");
    const head = element("thead"), headRow = element("tr"), body = element("tbody");
    for (const title of headings) {
      const cell = element("th", title);
      cell.scope = "col";
      headRow.append(cell);
    }
    head.append(headRow);
    for (const row of rows) {
      const tr = element("tr");
      for (const value of row) {
        const td = element("td");
        td.append(value instanceof Node ? value : document.createTextNode(String(value)));
        tr.append(td);
      }
      body.append(tr);
    }
    grid.append(element("caption", caption), head, body);
    wrap.append(grid);
    return wrap;
  }

  function fingerprint(title, value, id) {
    const wrap = element("div"), label = element("dt", title), hash = code(value);
    hash.className = "hash";
    if (id) hash.id = id;
    const description = element("dd");
    description.append(hash);
    wrap.append(label, description);
    return wrap;
  }

  function room(info, index) {
    const section = element("section", null, "room");
    section.id = info.id;
    const heading = element("h2", info.title);
    heading.id = info.id + "-heading";
    section.setAttribute("aria-labelledby", heading.id);
    section.append(paragraph("Room " + String(index + 1).padStart(2, "0"), "eyebrow"), heading);
    for (const text of info.intro) section.append(paragraph(text));
    return section;
  }

  async function verifyModel(files) {
    const result = await H.evaluate(files);
    if (result.evaluation.anchor_particle !== trust.anchor) throw new R.Refusal("REFUSE_ANCHOR", "The carrier is not the model pinned by this page.");
    return { ...result, files: Object.freeze(files) };
  }

  function frontDoor(section, snapshot) {
    const complete = full(snapshot), verification = snapshot.verification;
    const card = element("div", null, "card " + (complete ? "success" : "warning"));
    card.id = "verification-card";
    card.dataset.verification = complete ? "verified" : "partial";
    card.append(
      element("h3", complete ? "Verified in this browser" : "Partly verified: signatures not checked"),
      paragraph(complete
        ? "The browser checked the carried bytes, not a saved verdict or the story labels."
        : "Warning: this browser cannot verify Ed25519 signatures. Fingerprints and stream structure passed, but signatures have NOT been checked. Do not treat this as full verification.")
    );
    const checks = element("dl", null, "checks");
    for (const [label, result] of [
      ["Frames", verification.frames + " signed steps; content and position fingerprints match. " + Object.keys(snapshot.carried.identities).length + " signing identities are carried."],
      ["Signatures", complete ? verification.signatures + " Ed25519 signatures checked." : "Not checked: Ed25519 is unavailable."],
      ["Stream ownership", "Memory streams name their own owner. Body streams name their signer in the signature header; the stream is not a separate person."],
      ["Whole streams", verification.streams + " complete journals, with no gaps, repeats or broken links."]
    ]) {
      const item = element("div");
      item.append(element("dt", label), element("dd", result));
      checks.append(item);
    }
    card.append(checks, paragraph("These public test keys prove only this fictional example. They are not safe keys for real people or data.", "muted"));
    section.append(card);
    const hashes = element("dl");
    hashes.append(
      fingerprint("Anchor: the pinned identity of this model Hive", snapshot.evaluation.anchor_particle, "anchor-particle"),
      fingerprint("Derived state particle: the fingerprint of the rules and membership worked out here", snapshot.evaluation.state_particle, "state-particle")
    );
    section.append(hashes, paragraph("A particle is a content fingerprint. The same data gives the same fingerprint on another device. The story and labels are never used as verification evidence.", "muted"));
  }

  function residents(section, snapshot) {
    const evaluation = snapshot.evaluation, policy = evaluation.policy;
    section.append(paragraph("Policy v" + policy.version + " is active. Who decides: " + whoDecides(policy) + ". A new request needs " + policy.admit.quorum +
      (policy.admit.quorum === 1 ? " grant" : " grants") + " from members these rules let decide" +
      (policy.admit.attested ? ", and a confirmed key." : ". Key confirmation is not required by this policy.")));
    const rows = evaluation.state.members.map((rappid) => {
      const member = evaluation.members[rappid], identity = element("div");
      identity.append(element("strong", person(rappid)), element("code", short(rappid.split(":").pop()), "identity"));
      let how = "Founder: signed acceptance of the anchor.", evidence = "The anchor names this founder.";
      if (member.how === "admitted") {
        const version = evaluation._policy(member.under).version;
        how = member.legacy ? "Legacy: joined on the old system; decided under policy v" + version + "." : "Admitted by grants under policy v" + version + ".";
        evidence = "Granted by " + member.grants.map(firstName).join(", ") + ".";
      }
      return [identity, how, evidence];
    });
    section.append(table("Who belongs in this copy", ["Resident", "How they got in", "Why"], rows, "resident-table"));
    const oldGrants = snapshot.records.filter((record) => record.kind === "hive2.grant" &&
      record.frame.payload.anchor === evaluation.anchor_particle && evaluation.legacy_joins.has(record.frame.payload.request));
    if (oldGrants.length) {
      const card = element("div", null, "card"), history = element("ol", null, "waiting-list");
      card.id = "legacy-request-history";
      const pinned = policy.migrate_pending === "keep-pinned";
      card.append(element("h3", pinned ? "An old request keeps who decides" : "An old request under this copy's rules"),
        paragraph(pinned
          ? "Keeping a request's earlier rules means keeping who may grant it, not just how many grants it needs. These are the signed responses to requests from the old system."
          : "This copy explicitly re-decides pending requests under the new rules. These are the signed responses to requests from the old system."));
      const refusals = new Map(evaluation.refusals.map((item) => [item.wave, item]));
      for (const record of oldGrants) {
        const item = element("li"), payload = record.frame.payload;
        const time = element("time", record.utc.replace("T", " ").replace("Z", " UTC"));
        time.dateTime = record.utc;
        item.append(time, paragraph(firstName(record.owner) + " responds to " + firstName(payload.member) + "'s request."));
        if (refusals.has(record.wave)) {
          const refusal = refusals.get(record.wave);
          item.append(paragraph("Refused: " + refusal.code + ". " + refusalText({ code: refusal.code, message: refusal.reason })));
        } else {
          const counted = evaluation.events.some((event) => event.wave === record.wave && event.event === "granted a pending request");
          const member = R.own(evaluation.members, payload.member);
          item.append(paragraph(counted ? "Grant counted." : "No grant took effect."));
          if (member && member.request === payload.request) {
            item.append(paragraph(firstName(payload.member) + " is in under policy v" + evaluation._policy(member.under).version +
              ". Who decides under those rules: " + whoDecides(evaluation._policy(member.under)) + "."));
          } else if (R.hasOwn(evaluation.pending, payload.request)) item.append(paragraph("The request is still waiting."));
        }
        history.append(item);
      }
      card.append(history);
      section.append(card);
    }
    section.append(element("h3", "Waiting at the door"));
    const pending = R.sortedCodePoints(Object.keys(evaluation.pending));
    if (!pending.length) section.append(paragraph("No requests are waiting."));
    else {
      const list = element("ul", null, "waiting-list");
      for (const key of pending) {
        const request = evaluation.pending[key], rule = evaluation._policy(request.pinned);
        const count = Array.from(request.grants).filter((member) => evaluation._decides(rule, member)).length;
        const confirmed = Array.from(evaluation.attested[request.requester] || []).some((member) => member !== request.requester && R.hasOwn(evaluation.members, member));
        const item = element("li"), progress = element("progress");
        progress.max = rule.admit.quorum;
        progress.value = Math.min(count, rule.admit.quorum);
        progress.setAttribute("aria-label", firstName(request.requester) + ": " + count + " of " + rule.admit.quorum + " grants");
        item.append(element("strong", person(request.requester)), progress,
          paragraph(count + " of " + rule.admit.quorum + " grants. " + (confirmed ? "Key confirmed." : "Key not confirmed.") +
            " Rules: policy v" + rule.version + (request.legacy ? ", carried over from the old system." : ".") + " Who decides: " + whoDecides(rule) + "." +
            (!rule.admit.attested ? " These rules do not require key confirmation." : "")));
        list.append(item);
      }
      section.append(list);
    }
    section.append(element("h3", "Quarantined messages"));
    if (!evaluation.quarantined.length) section.append(paragraph("None. No messages are waiting outside membership."));
    else {
      section.append(paragraph("Kept, not deleted. These messages do not enter the shared view until the sender is admitted. Quarantined messages never teach the Hive new shapes or affect the lens laws."));
      const list = element("ul");
      for (const record of evaluation.quarantine) {
        const item = element("li", person(record.owner) + ": " + titleOf(record));
        if (R.hasOwn(record.frame.payload, "invoice")) item.append(paragraph("The extra invoice field teaches the Hive nothing while this message is quarantined.", "muted"));
        list.append(item);
      }
      section.append(list);
    }
  }

  function renovation(section, snapshot) {
    const evaluation = snapshot.evaluation;
    const preserved = before.records.filter((old) => snapshot.records.some((record) => record.wave === old.wave && R.b64encode(record.raw) === R.b64encode(old.raw))).length;
    const card = element("div", null, "card " + (full(before) && preserved === before.records.length ? "success" : "warning"));
    card.append(element("h3", full(before) ? "The before copy verifies too" : "Before copy: signatures not checked"),
      paragraph(before.records.length + " original frames checked for fingerprints, stream ownership and complete journals." +
        (full(before) ? " All their signatures verify." : " Ed25519 is unavailable; their signatures remain unchecked.")),
      paragraph(preserved === before.records.length
        ? "Nothing rewritten: all " + preserved + " original frames are still present byte for byte."
        : preserved + " of " + before.records.length + " original frames are preserved in this copy. This is not the complete furnished migration."));
    section.append(card);
    const declaration = before.records.find((record) => record.wave === evaluation.legacy_declaration);
    if (declaration) {
      const declared = H.check_legacy_declaration(declaration);
      section.append(paragraph("The first step belongs to the rapp-hive/1 Mother Hive stream. Its stream name is contoso-hive, but it is a journal, not a resident or a signing identity. " +
        firstName(declared.owner) + ", the declared owner, signed its first frame."));
    }
    const joins = new Set(snapshot.records.filter((record) => record.kind === "hive2.join" && record.frame.payload.policy === evaluation.anchor.policy).map((record) => record.wave));
    const steps = snapshot.records.filter((record) => record.frame.payload.anchor === evaluation.anchor_particle &&
      (record.kind === "hive2.accept" || joins.has(record.wave) || (record.kind === "hive2.grant" && joins.has(record.frame.payload.request))));
    const verbs = { "hive2.accept": "Accepted the anchor as founder", "hive2.join": "Signed their own request to join", "hive2.grant": "Granted a returning member's request" };
    section.append(table("The migration steps, each signed by its own identity", ["Who", "Step", "Signature"], steps.map((record) =>
      [person(record.owner), verbs[record.kind], record.signature === "verified" ? "Verified" : "Not checked"])));
    section.append(element("h3", "The rules can change without moving the goalposts"));
    const rules = evaluation.policy_chain.map((particle) => evaluation._policy(particle));
    section.append(table("Policies that became active", ["Policy", "Who decides", "Admission", "Requests already waiting"], rules.map((policy) => [
      "v" + policy.version,
      whoDecides(policy),
      policy.admit.quorum + (policy.admit.quorum === 1 ? " grant" : " grants") + (policy.admit.attested ? " + confirmed key" : ""),
      policy.migrate_pending === "keep-pinned" ? "Keep the rules they started with" : "Re-decide under this policy"
    ])));
    section.append(paragraph(evaluation.policy.migrate_pending === "keep-pinned"
      ? "The active rules let " + (evaluation.policy.deciders === H.ALL_MEMBERS ? "every member decide. " : whoDecides(evaluation.policy) + " decide. ") +
        "Pending requests keep their earlier rules, including who decides. An old request can still need the steward's one grant; another member's approval does not replace it."
      : "In this copy, the active policy explicitly moves pending requests onto its new rules. They are re-decided, not silently grandfathered."));
  }

  function schemasAndLenses(section, snapshot) {
    const evaluation = snapshot.evaluation;
    const rows = R.sortedCodePoints(Object.keys(evaluation.schemas)).map((particle) => {
      const schema = evaluation.schemas[particle], hash = code(short(particle));
      hash.title = particle;
      const mappers = evaluation._mappers(particle).map(([id]) => id + " v" + evaluation.lens_objects[evaluation.active[id]].version);
      return [hash, schema.tags.operation || schema.kind, element("span", R.sortedCodePoints(Object.keys(schema.payload)).join(", "), "fields"), mappers.join(", ") || "Waiting for a lens"];
    });
    section.append(table("Message shapes (field names, never message values)", ["Schema particle", "Operation", "Fields", "Mapped by"], rows, "schema-table"),
      element("h3", "The lens history"));
    const history = element("ol", null, "lens-history");
    for (const particle of evaluation.history) {
      const lens = evaluation.lens_objects[particle], item = element("li");
      item.append(element("strong", lens.id + " v" + lens.version),
        document.createTextNode(evaluation.derived.includes(particle)
          ? " - learned automatically: only new fields were added."
          : " - authored rules, adopted by the required members."),
        document.createTextNode(evaluation.active[lens.id] === particle ? " Active now." : " Kept so older shapes can still be read."));
      history.append(item);
    }
    section.append(history);
    const broken = evaluation.refusals.filter((item) => item.code === "REFUSE_LENS_LAW");
    for (const refusal of broken) {
      const record = snapshot.records.find((item) => item.wave === refusal.wave);
      const particle = record.frame.payload.object, lens = evaluation.lens_objects[particle];
      const votes = evaluation.tallies.get("lens:" + particle);
      const card = element("div", null, "card warning");
      card.append(element("h3", lens.id + " v" + lens.version + ": refused despite " + votes.size + " signatures"),
        paragraph("This careless successor would change what an old task means. The lens laws refused it; it never became active."),
        paragraph(refusal.reason, "muted"), code(refusal.code));
      section.append(card);
    }
    section.append(element("h3", "A waiting shape does not stop the house"));
    if (!evaluation.exhausts.length) section.append(paragraph("Every admitted message has one working lens."));
    for (const waiting of evaluation.exhausts) {
      const schema = evaluation.schemas[waiting.schema];
      section.append(paragraph((schema.tags.operation || schema.kind) + ": " + waiting.waiting.length +
        (waiting.waiting.length === 1 ? " message waits" : " messages wait") +
        (waiting.code === "no-lens" ? " for a lens." : " because its translation could not finish (" + waiting.code + ").") +
        " The other mapped messages keep working."));
    }
    if (evaluation.quarantine.some((record) => R.hasOwn(record.frame.payload, "invoice"))) {
      section.append(paragraph("The quarantined invoice field is not among the learned shapes above. Only members' messages teach the Hive a new shape.", "muted"));
    }
    section.append(paragraph("A field can be accepted yet left out of the shared view. In the furnished model, priority taught automatic v2; the renamed summary field needed authored v3. Crossings tell you what stays behind.", "muted"));
  }

  function crossingReason(error, snapshot, wave, member) {
    if (error.code !== "REFUSE_CROSSING") return refusalText(error);
    const entry = snapshot.evaluation.views.find((item) => item.source === wave);
    const targetSchemas = snapshot.evaluation.content.filter((record) => record.owner === member)
      .map((record) => snapshot.evaluation.schemas[snapshot.evaluation.frame_schema[record.wave]]);
    if (entry && entry.value.due === null && targetSchemas.length && targetSchemas.every((schema) => schema.payload.due === "string")) {
      return firstName(member) + "'s app requires a due date, and the Hive will not invent one.";
    }
    return refusalText(error);
  }

  function crossings(section, snapshot) {
    const evaluation = snapshot.evaluation;
    const mapped = evaluation.views.map((view) => snapshot.records.find((record) => record.wave === view.source));
    const source = select("cross-message", mapped.map((record) => [record.wave, firstName(record.owner) + " - " + titleOf(record)]));
    const member = select("cross-member", evaluation.state.members.map((rappid) => [rappid, person(rappid)]));
    const other = evaluation.state.members.find((rappid) => mapped.length && rappid !== mapped[0].owner);
    if (other) member.value = other;
    const controls = element("div", null, "controls grid");
    controls.append(field("A message to carry", source), field("Receiving resident", member));
    const result = element("div");
    result.id = "cross-result";
    const preview = element("blockquote");
    preview.id = "cross-source-preview";
    const resetResult = () => {
      const record = mapped.find((item) => item.wave === source.value);
      preview.textContent = record ? firstName(record.owner) + ": " + titleOf(record) : "No mapped message in this copy.";
      result.replaceChildren(paragraph("Choose a message and press Try this crossing. No data will be changed.", "muted"));
    };
    source.addEventListener("change", resetResult);
    member.addEventListener("change", resetResult);
    resetResult();
    const run = button("Try this crossing", "cross-run", () => action("Trying the crossing in this browser...", async () => {
      let proposal;
      try { proposal = await H.cross_to_member(evaluation, source.value, member.value); }
      catch (error) {
        if (!(error instanceof R.Refusal)) throw error;
        const card = element("div", null, "result warning");
        card.dataset.outcome = "refused";
        card.append(element("h3", "Refused: " + crossingReason(error, snapshot, source.value, member.value)), code(error.code),
          paragraph("The original message is unchanged. No proposal has been signed.", "muted"));
        result.replaceChildren(card);
        status("Crossing refused. " + crossingReason(error, snapshot, source.value, member.value));
        return;
      }
      const card = element("div", null, "result");
      card.dataset.outcome = "proposal";
      const payload = element("pre", JSON.stringify(proposal.payload, null, 2));
      payload.setAttribute("aria-label", "Unsigned proposal payload");
      card.append(element("h3", "Unsigned proposal"), paragraph("For " + firstName(member.value) + "'s app. Only that owner could sign it; this page will not."),
        payload,
        element("h4", "What could not cross"),
        paragraph("Left out by the sender's lens: " + (proposal.dropped_by_forward_lens.join(", ") || "nothing") + "."),
        paragraph("Not expressible in the receiving app: " + (proposal.not_expressible_in_target.join(", ") || "nothing") + "."),
        paragraph(proposal.lossless ? "Lossless: no source fields were left out." : "Some information stays behind. The source message still has it."));
      const details = element("details");
      details.append(element("summary", "Proposal fingerprint and the lenses used"),
        paragraph("Payload particle: " + proposal.payload_particle, "hash"),
        paragraph("Forward: " + proposal.through.forward.id + " v" + proposal.through.forward.version +
          ". Reverse: " + proposal.through.reverse.id + " v" + proposal.through.reverse.version + "."));
      card.append(details);
      result.replaceChildren(card);
      status("Unsigned proposal ready. " + (proposal.lossless ? "No source fields were left out." : "Some information could not cross; see the fields below."));
    }));
    run.disabled = !mapped.length || !evaluation.state.members.length;
    const actions = element("div", null, "actions");
    actions.append(run);
    section.append(controls, preview, actions, result);
  }

  function agreement(section, snapshot) {
    if (!snapshot.manifests.length) { section.append(paragraph("There are no member manifests in this copy yet.")); return; }
    section.append(table("Claims checked against the exact frames each device named", ["Resident", "Claim", "Position", "Frames behind"], snapshot.manifests.map((item) => [
      person(item.by), item.verdict, item.position === "agrees" ? "Agrees with this copy" : item.position === "behind" ? "Behind" :
        (item.code ? item.code + ": " + refusalText({ code: item.code }) : "Cannot recompute"),
      item.missing_frames === undefined ? "Unknown" : item.missing_frames
    ])));
    const divergent = snapshot.manifests.filter((item) => item.verdict === "divergent").length;
    const unverified = snapshot.manifests.filter((item) => ["malformed", "unverifiable"].includes(item.verdict)).length;
    const card = element("div", null, "card " + (divergent || unverified ? "warning" : ""));
    card.append(paragraph(divergent ? divergent + " divergent manifest(s): the claimed state does not match its own steps." : "No divergent manifests in this copy."),
      paragraph(unverified ? unverified + " claim(s) could not be recomputed." : "Being behind is not the same as being wrong. A device can be consistent about the steps it has seen."));
    if (!full(snapshot)) card.append(paragraph("These calculations were checked, but manifest signatures could not be verified.", "muted"));
    section.append(card);
  }

  function timeline(section, snapshot) {
    const list = element("ol", null, "timeline");
    list.id = "frame-timeline";
    const refusals = new Map(snapshot.evaluation.refusals.map((item) => [item.wave, item]));
    const declaration = snapshot.records.find((record) => record.wave === snapshot.evaluation.legacy_declaration);
    for (const record of snapshot.records) {
      const item = element("li"), meta = element("div", null, "timeline-meta");
      item.dataset.wave = record.wave;
      const time = element("time", record.utc.replace("T", " ").replace("Z", " UTC"));
      time.dateTime = record.utc;
      meta.append(time, element("span", record.signature === "verified" ? "Verified" : "Signature not checked", "badge " + (record.signature === "verified" ? "verified" : "partial")));
      const narration = notes.get(record.wave) || snapshot.evaluation.events.filter((event) => event.wave === record.wave).map((event) => event.event).join("; ") || titleOf(record);
      item.append(meta, element("h3", person(record.owner)), paragraph(narration));
      if (record.legacy) {
        item.append(paragraph(declaration && record.stream === declaration.stream
          ? "Stream: the rapp-hive/1 Mother Hive stream. Signed by " + firstName(record.owner) + ", not by a separate Hive identity."
          : "Body stream: content signed by " + firstName(record.owner) + ".", "muted"));
      }
      if (refusals.has(record.wave)) {
        const refusal = refusals.get(record.wave);
        item.append(paragraph("The signed request was refused: " + refusal.code + ". " + refusalText({ code: refusal.code, message: refusal.reason }), "muted"));
      }
      const details = element("details");
      details.append(element("summary", "Inspect this signed step: " + record.kind + " / " + short(record.wave)), element("pre", JSON.stringify(record.frame, null, 2)));
      item.append(details);
      list.append(item);
    }
    section.append(paragraph(snapshot.records.length + " frames, in order."), list);
  }

  function textField(record) {
    for (const key of ["title", "summary", "text", "emoji"]) if (typeof R.own(record.frame.payload, key) === "string" && record.frame.payload[key]) return key;
    return null;
  }

  function tryIt(section, snapshot) {
    section.append(element("h3", "Change a word. Break the seal."));
    const eligible = new Set([...snapshot.evaluation.content, ...snapshot.evaluation.quarantine].map((record) => record.wave));
    const messages = snapshot.records.filter((record) => eligible.has(record.wave) && textField(record) !== null);
    const source = select("tamper-message", messages.map((record) => [record.wave, firstName(record.owner) + " - " + titleOf(record)]));
    const original = element("blockquote");
    original.id = "tamper-original";
    const find = element("input"), replace = element("input");
    find.id = "tamper-find";
    replace.id = "tamper-replace";
    find.type = replace.type = "text";
    find.maxLength = replace.maxLength = 100;
    replace.value = "Changed";
    const result = element("div");
    result.id = "tamper-result";
    function pick() {
      const record = messages.find((item) => item.wave === source.value);
      const text = record ? record.frame.payload[textField(record)] : "";
      original.textContent = text || "No editable message in this copy.";
      find.value = text.trim().split(/\s+/)[0] || "";
      result.replaceChildren();
    }
    source.addEventListener("change", pick);
    pick();
    const controls = element("div", null, "controls");
    const words = element("div", null, "grid");
    words.append(field("Word to change", find), field("Replace it with", replace));
    controls.append(field("Message to test", source), original, words);
    const run = button("Change a word and re-verify the copy", "tamper-run", () => action("Checking an edited copy. The original is untouched...", async () => {
      const record = messages.find((item) => item.wave === source.value), key = textField(record);
      if (!find.value || !replace.value || find.value === replace.value || !record.frame.payload[key].includes(find.value)) {
        const error = new R.Refusal("REFUSE_DEMO_INPUT", "Choose a word in the message and a different, nonempty replacement.");
        showRefusal(result, "Nothing changed", error);
        status(error.message);
        return;
      }
      const frame = JSON.parse(R.canonString(record.frame));
      frame.payload[key] = frame.payload[key].replace(find.value, () => replace.value);
      const files = Object.assign(Object.create(null), snapshot.files);
      files[record.path] = R.b64encode(R.canonical(frame));
      try { await verifyModel(files); }
      catch (error) {
        if (!(error instanceof R.Refusal)) throw error;
        showRefusal(result, "Tamper refused", error, "Only the test copy was edited. Your last checked Hive is unchanged.");
        status("Tamper refused: " + error.code + ". The original Hive is unchanged.");
        return;
      }
      throw new Error("The changed message unexpectedly passed verification.");
    }));
    run.disabled = !messages.length;
    const actions = element("div", null, "actions");
    actions.append(run);
    section.append(controls, actions, result, element("h3", "Take a copy with you"));
    section.append(paragraph("The download is a JSON object of file names and base64 bytes. It carries the signed data, not the story or a saved verdict.", "muted"));
    const exportActions = element("div", null, "actions");
    exportActions.append(button("Download carrier bundle", "export-bundle", () => action("Preparing the local download...", async () => {
      const blob = new Blob([R.canonical(snapshot.files, MAX_BUNDLE_BYTES)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      downloads.add(url);
      const link = element("a");
      link.href = url;
      link.download = "model-hive-bundle.json";
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => { URL.revokeObjectURL(url); downloads.delete(url); }, 1000);
      status("Download started: model-hive-bundle.json. No network request was made.");
    })));
    section.append(exportActions, element("h3", "Open a carrier bundle"));
    const file = element("input");
    file.id = "import-file";
    file.type = "file";
    file.accept = ".json,application/json";
    file.setAttribute("aria-describedby", "import-help");
    const help = paragraph("Use this tour's JSON download format. Maximum 8 MiB, with at most 1 MiB per carried file. Only this model's anchor is accepted. An import replaces the view only after the checks finish.", "muted");
    help.id = "import-help";
    const importResult = element("div");
    importResult.id = "import-result";
    const importActions = element("div", null, "actions");
    importActions.append(
      button("Verify and open bundle", "import-bundle", () => action("Verifying the selected bundle. Keeping the current copy until it passes...", async () => {
        let next;
        try {
          const chosen = file.files[0];
          if (!chosen) throw new R.Refusal("REFUSE_IMPORT", "Choose a JSON bundle file first.");
          if (!chosen.size || chosen.size > MAX_BUNDLE_BYTES) throw new R.Refusal("REFUSE_JSON_SIZE", "The bundle must be nonempty and no larger than 8 MiB.");
          const bytes = new Uint8Array(await chosen.arrayBuffer());
          const files = R.parseCanonical(bytes, MAX_BUNDLE_BYTES);
          next = await verifyModel(files);
        } catch (error) {
          if (!(error instanceof R.Refusal)) throw error;
          const retained = full(snapshot) ? "Still showing your last verified Hive." : "Still showing your last partly checked Hive.";
          showRefusal(importResult, "Import refused", error, retained);
          status("Import refused: " + error.code + ". " + retained);
          return;
        }
        current = next;
        render();
        document.getElementById("import-result").append(paragraph(full(next) ? "Imported bundle verified and opened." : "Imported bundle opened with a warning: signatures were not checked."));
        document.getElementById("import-bundle").focus({ preventScroll: true });
        status(full(next) ? "Imported bundle verified. The tour now reflects this copy." : "Partly verified import: signatures not checked. The warning remains visible.");
      })),
      button("Return to the furnished model", "reset-model", () => action("Rechecking the original furnished model...", async () => {
        current = await verifyModel(originalFiles);
        render();
        document.getElementById("reset-model").focus({ preventScroll: true });
        status(full(current) ? "Original model restored and verified." : "Original model restored. Signatures are still unchecked.");
      }), true)
    );
    section.append(field("JSON bundle file", file), help, importActions, importResult);
  }

  function render() {
    const fragment = document.createDocumentFragment();
    const renderers = {
      "front-door": frontDoor, residents, renovation, "schemas-and-lenses": schemasAndLenses,
      crossings, agreement, timeline, "try-it": tryIt
    };
    lessons.rooms.forEach((info, index) => {
      const section = room(info, index);
      renderers[info.id](section, current);
      fragment.append(section);
    });
    main.replaceChildren(fragment);
    main.setAttribute("aria-busy", "false");
    document.documentElement.dataset.ready = full(current) ? "verified" : "partial";
  }

  function shell() {
    const skip = element("a", "Skip to the tour", "skip-link");
    skip.href = "#tour-main";
    const wrap = element("div", null, "shell"), header = element("header");
    header.append(paragraph("Contoso Model Hive / an offline open house", "eyebrow"), element("h1", lessons.title), paragraph(lessons.subtitle, "subtitle"));
    const warning = element("aside", null, "synthetic");
    warning.setAttribute("aria-label", "Synthetic data warning");
    warning.append(paragraph(lessons.synthetic));
    header.append(warning);
    const nav = element("nav", null, "room-nav");
    nav.setAttribute("aria-label", "Tour rooms");
    lessons.rooms.forEach((info, index) => {
      const link = element("a");
      link.href = "#" + info.id;
      link.append(element("span", String(index + 1).padStart(2, "0")), document.createTextNode(info.title));
      nav.append(link);
    });
    live = paragraph("Checking the embedded Hive and its before copy...", "live-status");
    live.id = "live-status";
    live.setAttribute("role", "status");
    live.setAttribute("aria-live", "polite");
    live.setAttribute("aria-atomic", "true");
    main = element("main");
    main.id = "tour-main";
    main.tabIndex = -1;
    main.setAttribute("aria-busy", "true");
    main.append(paragraph("Checking fingerprints, signatures, stream ownership and whole streams. Please wait.", "card"));
    const footer = element("footer");
    footer.append(paragraph("A public, synthetic model. All verification happens in this tab. No accounts, network calls or signing keys are needed."));
    wrap.append(header, nav, live, main, footer);
    document.body.append(skip, wrap);
  }

  async function start() {
    lessons = block("tour-lessons");
    story = block("tour-story");
    trust = block("model-trust");
    originalFiles = block("model-carrier", MAX_BUNDLE_BYTES);
    const beforeFiles = block("before-carrier", MAX_BUNDLE_BYTES);
    for (const item of story.story) notes.set(item.wave, item.note);
    shell();
    [current, before] = await Promise.all([
      verifyModel(originalFiles),
      (async () => {
        const carried = await H.load(beforeFiles), records = await H.verify_frames(carried);
        return { carried, records, files: beforeFiles, verification: carried.verification };
      })()
    ]);
    render();
    status(full(current) && full(before)
      ? "Tour ready. " + current.records.length + " signed steps checked, plus " + before.records.length + " original steps in the before copy."
      : "Warning: this browser cannot check Ed25519 signatures. This is only partial verification.");
  }

  window.addEventListener("pagehide", () => {
    for (const url of downloads) URL.revokeObjectURL(url);
    downloads.clear();
  });
  start().catch((error) => {
    document.documentElement.dataset.ready = "refused";
    const message = error instanceof R.Refusal ? error.code + ". " + refusalText(error) : error.message || String(error);
    if (main) {
      main.setAttribute("aria-busy", "false");
      main.replaceChildren(element("h2", "The tour could not be verified"), paragraph(message, "card danger"));
      status("Tour refused. " + message);
    } else {
      document.body.append(element("h1", "The tour could not open"), paragraph(message));
    }
    if (!(error instanceof R.Refusal)) console.error(error);
  });
})();
