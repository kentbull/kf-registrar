# kf-registrar

`kf-registrar` is the KERI Foundation registrar service: a long-running node that
governs ACDC transaction event logs (TELs) and serves them in bulk to
observers only (see kf-observer).

It is the ACDC counterpart of a witness. Witnesses serve KELs; this process
serves TELs. Wallets and verifiers obtain TEL status from an observer. Explicitly
allowlisted publishers may submit public registry evidence to the registrar.

## Dual HTTP

Modeled on [`witness-hk`](https://github.com/keri-foundation/witness-hk):

- **Internal / admin** (default `127.0.0.1:6631`): controller API for the
  registrar/issuer habitat. Create/list registries, append `bup`, read its own
  TEL data **without** running an observer. Also
  `POST /ingest` for hosting pre-built, KEL-anchored TEL events (e.g.
  presentation registries built in a wallet): JSON
  `{ "kel": "<CESR>", "tel": "<CESR rip/bup>" }` → verify with the service-owned Kevery, Parser and core Regery
  and store for observer bulk. This is controller publish, not a wallet status
  query.
- **External** (default `127.0.0.1:6632`): signed V2 `qry` POST (`r: "tels/bulk"`
  or `"regs"`) authenticated with KRAM and restricted to configured observer
  AIDs. Response is concatenated CESR of accepted `rip`/`bup` events.

There is no registrar pool, no TEL receipts, and no wallet-shaped
`GET /query?typ=tel`. Wallets and verifiers must not query this service for
TEL status; they talk to an observer.

### Account enrollment

The trusted internal listener also provides `PUT /accounts/{aid}` with JSON
`{"roles": ["publisher"], "kel": "<public CESR KEL>"}`. Roles are `publisher`
and/or `observer`; PUT replaces that account's dynamic roles. KERIpy verifies
the supplied KEL and requires an accepted account AID before permissions are
persisted. Enrollment accepts no TEL, credential, private key or local habitat.

PUT and `GET /accounts/{aid}` return `{aid, roles, service}`, where `service` is
the registrar's AID. `DELETE /accounts/{aid}` returns 204 idempotently and revokes
dynamic permissions while retaining public evidence and any operator-configured
`--publisher`/`--observer` permissions. The allowlist survives service restart in
the existing registry database. External `/ingest` is always available, denying
publishers until configured or enrolled; every request still needs its ordinary
KERI authentication.

This private API trusts its administrator, such as the configured kf-boot
backend client. `--boothost` now requires a literal loopback IP (`localhost`
selects `127.0.0.1`); remote and wildcard binds are refused before service setup.
It uses plain HTTP on loopback, independently of the public listener's TLS
configuration. Keep this administration listener private. A public service URL
alone does not activate an account.

## Requirements

- Python >= 3.14
- `libsodium` (required by the `keri` package)

### Installing libsodium

**macOS:**

```bash
brew install libsodium
```

**Ubuntu/Debian:**

```bash
sudo apt-get install libsodium-dev
```

## Installation

The maintained service pins `keri` to a complete published `kentbull/keripy`
commit in `pyproject.toml` and `uv.lock`; it does not depend on a sibling checkout:

```bash
cd kf-registrar
uv sync --all-extras
```

Or with pip:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e '.[dev]'
```

Standalone clones without the sibling tree will pull `keri` from git.
## Running

```bash
kf-registrar start \
  --alias registrar \
  --config-dir /path/to/scripts \
  --config-file kf-registrar \
  --host 127.0.0.1 \
  --http 6632 \
  --boothost 127.0.0.1 \
  --bootport 6631 \
  --observer <observer-aid>
```

`--config-dir` must point at the directory *above* `keri/cf/` (KERI appends
`keri/cf/` when locating the file). For this repo that is `scripts/`.

Repeat `--observer` for each allow-listed observer AID, or list them in
`scripts/keri/cf/kf-registrar.json` under `kf-registrar.observers`.

### Publish a registry snapshot

Bootstrap a separate publisher's signed KEL into the registrar with `--kel` and
allow its AID with `--publisher`. The publisher command opens only that existing
publisher keystore; it does not open the issuer's live store:

```bash
kf-registrar publish --name publisher --base operations --alias publisher \
  --input issued.cesr --registry <registry-said> \
  --url https://registrar.example --ca /path/to/ca.pem --timeout 20
```

Use `--passcode` or `KLI_KEYSTORE_PASSCODE` for an encrypted publisher. An IP URL
also requires `--certedhost` with the explicit certificate hostname. Redirects
are refused. The input is read once as a complete mixed CESR snapshot: only
top-level public KEL support and the selected registry's complete RIP/BUP history
are published. Credential/IPEX disclosure, arbitrary held openings and custody
are excluded. Incomplete or ambiguous selected history fails before transmission.
Success requires the registrar's exact accepted head to match the input snapshot,
with no pending or rejected evidence; it is not a claim about newer remote state.

## Tests

```bash
export DYLD_FALLBACK_LIBRARY_PATH="$(brew --prefix)/lib:/usr/local/lib:/usr/lib"
export DYLD_LIBRARY_PATH="$(brew --prefix)/lib"
pytest tests/
```

On Linux, libsodium install is enough; the `DYLD_*` exports are macOS-only.

## Evidence ownership

The registrar owns one concrete KEL/TEL processing lifecycle, one KRAM pruner
and its ordinary escrow pass. Request signatures and the explicit observer and
publisher allowlists remain mandatory; there is no observer freshness contract.
Public services hold no registry roots.

Authorized publication may explicitly disclose one exact BSQ/BSS opening with a
BUP. The app verifies its BLID and retains it only after ordinary TEL acceptance.
If the exact BUP is in the core TEL missing-anchor or out-of-order escrow, one
app-owned pending-opening table preserves only that canonical proof across
restart. Acceptance promotes it through `RegistryStore.putOpening`; rejected or
removed dependencies discard it. Pending proofs are never served. This adds no
second event queue, acceptance engine or retry service.

Core TEL cloning remains body-only. The registrar's HTTP export is always the
full-evidence form and explicitly adds openings disclosed by authorized publishers or authored by the local controller;
ordinary raw intake does not authorize publication. The three-actor publication,
independent verification and missing-KEL restart tests exercise these boundaries.
Full service/network and end-to-end qualification remain separate.
