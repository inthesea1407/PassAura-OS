# Store review model — design review

Status: design review only. Nothing here is built, audited, or run on real
hardware. CI-tested code only where a document says so.

Question: when POS has a store, what does "reviewing" a submission mean, who
signs what, and how does a device learn the outcome — and does that design
hold before we build it?

## 1. What exists today

- A device's only install authorization is a signed allowlist v2
  (`docs/ALLOWLIST_FORMAT.md`): entries bind `name`, optional `version`, and
  `sha256`; verification is signature, validity window, signer key valid and
  not retired, then monotonic sequence with digest binding.
- Allowlists reach devices either through the update channel
  (`docs/UPDATE_CLIENT_DESIGN.md`, `docs/UPDATE_TRANSPORT_HTTPS.md`) or
  paired with a `.deb` in the same signed manifest
  (`docs/UPDATE_INSTALL_HANDOFF.md`).
- Signing keys are owner-held and offline; rotation is documented
  (`docs/KEY_ROTATION.md`).
- The backend already has the account/admin/rate-limit pattern (Supabase:
  invites, memberships, admin panel; see `docs/BACKEND.md`).

## 2. The boundary that does not move

The device-side trust contract does not change when a store exists. The gate
verifies signatures, windows, sequences and digests. It never learns about
reviews, reviewer identities, or store accounts. Everything the store adds
lives on the store side; the only artifact that crosses onto a device is the
signed allowlist, exactly as today. This is the strongest property of the
design and every option below is judged against it.

## 3. What a review is

A review is a recorded, attributable decision over one immutable submission:
a specific `.deb` with a specific SHA-256. States:

    submitted -> in_review -> approved | rejected
    approved  -> published (entry appears in a later allowlist)
    published -> revoked   (entry removed in a later allowlist, higher sequence)

Reviews are append-only store-side records (who, what, when, why, outcome).
They are not signatures a device verifies.

## 4. Who signs

Two strictly separated key families:

1. **Release keys** (existing): sign allowlists and update manifests.
   Owner-held, offline, rotated per `docs/KEY_ROTATION.md`. The only keys
   devices trust.
2. **Reviewer identities** (store-side only): ordinary backend accounts with
   a reviewer role, exactly the pattern the admin panel already uses. A
   reviewer approval is an input to the release signing step, never a
   signature on anything a device reads.

**Rejected option: reviewer countersignatures embedded in the allowlist**
(a v3 format with m-of-n reviewer sigs). It adds a second on-device trust
root, a new verification path, and new rotation complexity for no device-side
gain: the gate already has a working contract, and quorum belongs to the
signing step, not the document. Rejection rationale matches the certificate
pinning rejection in `docs/UPDATE_TRANSPORT_HTTPS.md`: one root of trust,
kept small.

## 5. What a review checks

Honest split between what CI can do and what needs people.

Automatable now (free tools, CI-runnable):

- **Hash binding:** the reviewed artifact's SHA-256 equals the submitted
  SHA-256, re-computed at publish time too (anti-swap, see threat 2).
- **Safe names and metadata:** package name/version rules the gate already
  enforces (`pos-gate` rejects shell metacharacters, leading dashes,
  traversal).
- **`.deb` maintainer-script inspection:** a `.deb` runs `postinst`/`prerm`
  as root at install. Static inspection of `DEBIAN/` control files is
  automatable with the deb parsing already in `pos-gate::deb_identity`.
  This is the review item with real teeth: it catches the install-time code
  path, not runtime behavior.
- **Policy check:** a password/credential manager submission is rejected by
  policy — official builds enforce PassAura as the sole credential manager,
  and the store does not undermine that.
- **Smoke malware scan** (e.g. ClamAV, free): stated plainly as a smoke
  check, not detection capability.

Needs people (phase 3 of `docs/CLOSED_MODEL_AND_KERNEL_PATH.md`, not
buildable here): developer identity verification, intent and quality
judgment, a reviewer pool. The design must not claim these exist.

## 6. Threat model additions (store side)

Extends `docs/THREAT_MODEL.md`; same severity labels.

1. **Compromised reviewer account approves a malicious package.** Critical.
   Mitigations: m-of-n reviewer quorum required before the signing step;
   release signing stays a separate owner-controlled step; append-only
   review records; revocation path (below) with its propagation lag stated
   honestly.
2. **Artifact swap between review and publish.** High. The review and the
   allowlist entry bind the same SHA-256; the publish step re-hashes the
   artifact and refuses on mismatch (same TOCTOU pattern as threat 1 in
   `docs/THREAT_MODEL.md`).
3. **Replay of a revoked package.** High. Devices reject lower sequences and
   same-sequence digest changes (`RollbackStore`). Known limit, already
   documented: the rollback file records intent, it is not hardware-backed
   rollback protection (`docs/ALLOWLIST_FORMAT.md` — its deletion resets
   the counter).
4. **Submission bombing / free-tier exhaustion.** Medium. Size caps per
   submission, per-account rate limits (the existing `0003_ratelimit`
   pattern), auth required — no anonymous submissions.
5. **Reviewer identity spoofing.** High. Reviewer roles granted and revoked
   by the admin path only, RLS policies on every store table, reviews carry
   the reviewer account id and are append-only.
6. **Malicious payload inside an otherwise clean package.** High, and not
   fully mitigable by automation: static checks cover maintainer scripts
   and metadata, not what the installed binary does at runtime. Stated as a
   limit; the mitigation is quorum, revocation, and (later, with people)
   real review.
7. **Release key compromise.** Out of scope here; the existing revocation
   and rotation path (`docs/KEY_ROTATION.md`) applies unchanged.

## 7. Store-side database model (design only)

No SQL is applied by the agent; the owner applies migrations to the live
database. Follows the existing migration style (`supabase/migrations`),
free tier, RLS everywhere, Deno tests like the existing backend tests.

- `store_apps(id, name, publisher_account_id, created_at, status)`
- `store_submissions(id, app_id, version, sha256, artifact_path,
  size_bytes, state, submitted_at)` — `state` covers the section-3 states.
- `store_reviews(id, submission_id, reviewer_account_id, decision, notes,
  created_at)` — append-only; one active review per reviewer per
  submission; a changed mind is a new row, never an edit.
- `store_reviewer_roles(account_id, granted_by, granted_at, revoked_at)`

RLS sketch: publishers insert and read their own submissions; reviewers
read `in_review` submissions and insert their own reviews; state changes
happen only through a security-definer function that checks quorum and
role validity, never through direct table writes. Pending submissions are
never publicly readable.

## 8. Publication and revocation flow

    m-of-n approvals -> publish step re-hashes artifact, refuses on mismatch
    -> owner release key signs the next allowlist v2 (offline)
    -> devices receive it through the update channel or the paired
       X.deb / X.allowlist.json convention.

Revocation is a new allowlist without the entry, at a higher sequence.
Propagation lag is whatever the update channel's poll interval is; stated
honestly, not hidden.

Paid listings are out of scope: the payment enforcement flag stays off and
no payment provider is contacted.

## 9. Conclusion: the design holds

The boundary in section 2 is what makes it hold: adding a store changes
nothing a device verifies, so the store can be built and iterated entirely
on the store side without touching the gate, the allowlist format, or the
update flow. The buildable-now half is real work: migrations + RLS + Deno
tests, the automated pre-review checks (including maintainer-script
inspection via `deb_identity`), and publish tooling that re-hashes and
hands a signed allowlist to the existing channel. The human half is
honestly out of reach until there are people to do it.

**Status (2026-11-27): item 2 built.** `pos-cli review-check` runs the
automated pre-review checks: submission hash binding, safe-name rules,
control-identity match, and maintainer-script heuristics over preinst,
postinst, prerm, postrm and config. `pos-gate::deb_identity` gained an
additive public `read_control_contents` for the script extraction; the
existing read path is unchanged and its tests still pass. Items 1 (SQL) and
3 (publish tooling) are not built; item 4 awaits the owner.

## Build notes (if and when approved)

1. `supabase/migrations/0004_store.sql`: section-7 tables, RLS, and a
   `publishable(submission_id)` security-definer function enforcing quorum.
   Deno tests mirror the existing backend test style. Owner applies to the
   live database; the agent never does.
2. Pre-review checker: hash re-check, safe-name rules, and `DEBIAN/`
   maintainer-script extraction using `pos-gate::deb_identity` parsing;
   new code gets unit tests with `build_minimal_deb`-style fixtures.
3. Publish tooling: re-hash, sign offline, emit through the update
   channel — no new transport work needed.
4. Quorum size m and reviewer count n are owner decisions; defaults in the
   design (2-of-3) are placeholders, not approvals.
