# Additive native evidence parity

This fork keeps the original controller API and bare-TEL bulk response by
default. The optional full-evidence service mode returns the supporting KEL and
framed TEL needed by an independent verifier. Signed publication is a separate,
opt-in external route authorized by explicit publisher AIDs. These are local
application profiles, not new KRAM or ACDC protocol semantics.

## Dependency and provenance

The upstream foundation is keri-foundation/kf-registrar
`bf14eac4d644275a13cbd3c5900cc2e4dd7c11d1` (Git records Evan Asakawa as its
author). Retained admin resources, dual-server layout and CLI derive from that
source. Attribution identifies source lineage, not personal responsibility for
this fork's changes.

The KERI dependency is Kent's qualified fork at
`4b1078e037c6f39dc398044e3436d071345d43a0`. The lock no longer resolves an
editable sibling checkout. Its required multidict 6.9.1 accounts for generated
wheel/hash changes relative to the old sibling dependency's 6.8.0.

## Changed symbol lineage

| Symbols | Origin and local decision |
|---|---|
| `Context.__init__`, `escrowDo`, `makeContext` | Upstream service composition adapted locally to shared `keri.app.evidencing.EvidenceContext`; one pruner/escrow owner and one registry backend. |
| `ControllerIngester.__init__`, `ingest`, `retryPending` | Original admin adapter replaced locally with framing plus shared Rever intake. Removes application-owned pending batches and direct acceptance; durable core escrows own recovery. |
| `groupTelEvents`, `parseTelStream` documentation | Existing parsing contract extended locally to public `upd` as well as `rip`/`bup`. |
| `loadExternalEnds`, `PublishEnd` methods | Local optional publisher route; policy and status mapping adapted from qualified KERIpy registrar at 4b1078e0. Authentication remains shared core KRAM. |
| `BulkQueryEnd.on_post` | Upstream endpoint retained, with local strict framing/native-version/authentication checks and explicit complete-evidence mode. Bare response remains default. |
| `test_evidence` helpers and tests | New local integration assertions, informed by KERIpy `test_native_services` at 4b1078e0; use genuine signatures and persistent escrow, never inject accepted rows. |

The registrar's network service is implemented here. It does not launch a KLI
registrar subprocess. Shared core evidence verification is a library dependency.
Local admin issuance remains available and external publication grants no
issuer signing authority or access to private registry derivation salts.

## Verification

The component Dockerfile installs the package into the qualified core image.
Tests disable pytest source-path injection and use Linux-owned named volumes;
no LMDB directory is bind-mounted from macOS. Nine tests pass: all seven original
service tests plus independent full-proof/public-update verification and durable
reopen recovery without TEL retransmission. This focused result is not the
multi-component end-to-end qualification or a Locksmith UI result.

## Operator entry point

`kf-registrar start --publisher AID --observer AID --full-evidence --kel FILE`
selects the additive evidence profile. Repeat role/bootstrap options as needed.
`KLI_KEYSTORE_PASSCODE` supplies the existing KLI passcode convention without
placing the secret in command arguments. The local controller API still uses
`--bootport`; external consumers use `--http`. Invalid or incomplete bootstrap
fails before binding the listeners.

`start.runRegistrar`, its parser additions and `serving.setup` bootstrap wiring
are local adaptations of the existing upstream entry point, informed by the
qualified KLI registrar startup. The new subprocess test launches the installed
`kf-registrar` binary and probes both actual sockets. All ten tests pass in the
installed-package container; this does not yet qualify the combined workflow.

The combined service profile advances the shared dependency to
`ae144adbadc10aa40a057d600fd4546f08275e1d`, the behavior-preserving observation
extraction. Registrar and observer now select the same core revision.

## Common runtime pin and source-review boundary

The additive qualification now uses KERIpy
`993b58266992b786d044fd3938e114a19d76f62f` and this component at
`917767dfaf8d06387529c1663b027c656984d4c4`. Earlier pins and results above are
historical checkpoints. The package declaration and lock select the same exact
core revision; no sibling editable source is required. The pin follow-up changes
no application symbol or protocol policy.

A fresh clone installed in the common Linux scenario image passes all 10
component tests. The clean multi-component story matrix is recorded separately;
a component suite alone does not establish that outcome. Existing changed-symbol
lineage remains the application source audit, with Git history retaining the
individual predecessor lines and contributors.

## Registrar PR 2 disposition

The inspected proposal is Jay-Alexander Elliot's
[`4af546a`](https://github.com/keri-foundation/kf-registrar/commit/4af546a29b3248b839626b8371db7ba0942c5340),
“preserve independent TEL submissions and repair replay heads.” Its
`_PendingSubmission`, `_restorePending`, `_clearSubmission` and application-owned
chain persistence address real pending/replay concerns in the donor service.

Those goals are retained, but that implementation is **superseded** here by the
shared core Rever's durable per-event escrows and atomic accepted-history owner.
`ControllerIngester.ingest` and `retryPending` delegate to that owner instead of
importing another pending table or writing accepted ordinals/heads themselves.
The donor PR is therefore design/comparison evidence, not a copied source claim.
The component's independent-proof and restart-without-retransmission tests,
together with the core conflict/replay regressions, cover the replacement
boundary. This does not claim a migration or automatic repair procedure for an
arbitrary database previously produced by the donor PR.
