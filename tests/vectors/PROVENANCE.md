# Where these vectors come from

These six files are copied byte for byte from this repository's `main` branch at commit
`83e039f` (the frozen rapp-hive/2 model home). Nothing was re-encoded or re-signed.

They are signed with PUBLIC test keys. Anyone can re-derive each key from its label:
`Ed25519PrivateKey.from_private_bytes(sha256(("rapp-hive/2:public-test-key/1\n" + "contoso-model-hive/" + slug).encode()).digest())`.
They prove nothing about a real person. Never use them for real data.

| File here | Path at `83e039f` | sha256 |
|---|---|---|
| `rapp-hive-1/identities/avery-laptop.121f71337e33.json` | `model/before/identities/avery-laptop.121f71337e33.json` | `c4384db430cc9efaedaed6eca351c00f6796061a146890f932b8b516cc7ebc0e` |
| `rapp-hive-1/identities/emery-kiosk.e3cb6fe1c662.json` | `model/before/identities/emery-kiosk.e3cb6fe1c662.json` | `ffe30321b9ff9ac51cf2dfc78fa466906c156756393423390fb8c1692bb347ca` |
| `rapp-hive-1/streams/contoso-hive.f2a17f3ba580/00000000.json` | `model/before/streams/contoso-hive.f2a17f3ba580/00000000.json` | `6650c72079f6b153648f40ee645f3c68c9e00167efbfefbe40fb2cc516d0146a` |
| `rapp-hive-1/streams/emery-kiosk.onboarding.e3cb6fe1c662/00000000.json` | `model/before/streams/emery-kiosk.onboarding.e3cb6fe1c662/00000000.json` | `8246ebc219160a1346ee3f51e1d9f113c6775161b566a907f7f57d1fce150c28` |
| `rapp-hive-2/identities/frankie-laptop.2a7d96c27554.json` | `model/hive/identities/frankie-laptop.2a7d96c27554.json` | `5179ecdc319e3ac792af6b5ac2f21da06859bd1e3e4ca0c9431d2f9cb7a62d90` |
| `rapp-hive-2/streams/frankie-laptop.hive.2a7d96c27554/00000000.json` | `model/hive/streams/frankie-laptop.hive.2a7d96c27554/00000000.json` | `b2647f0255511b9985e4f54832f9ed82c928328a97ce6095f9343b4cd91fb3ee` |

What they are:

- `rapp-hive-1/`: the rapp-hive/1 era. Avery's `hive.declaration` on the Mother Hive stream, and Emery's
  old onboarding `join-request` (a `memory.save` frame). Emery's request names the old Hive id
  `77086a0d3de14331843c1b8d1217090e5a849675f62265727f5bdb541507a9d8`.
- `rapp-hive-2/`: Frankie's pending `hive2.join`, which the rapp-hive/2 model never admitted. It names the
  rapp-hive/2 anchor `03972c7e8049b59134681ef9b1d7af369e4b06273d262691c5b28d6c48dcdce8`.

The tests check that all three frames still pass the agent's check with RAPP/1's hash and signature math (no signed
registry holds these keys, so that checks the bytes and their key, not who owns it). The example builder copies these
folders into the devices' Hives folders as the two "old Hives" of journey J12.
