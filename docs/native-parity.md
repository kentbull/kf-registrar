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
