# BUILD BRIEF — crypto-lab-export-grade

Binding spec: ./CRYPTO-LAB-TEMPLATE.md (gitignored copy of _MASTER-TEMPLATE.md).
Catalog root CLAUDE.md wins where they touch.
Lifecycle: Build → Teach → Look → Accessibility → README → Deploy.

## KEY FACTS PINNED (verify each before it enters shipped copy)

- TETRA (ETSI, 1995) is the police/military/critical-infrastructure radio standard
  used in 100+ countries. Its air-interface encryption has a family of ciphers
  TEA1-TEA4 (newer TEA5-7 exist). TEA1 and TEA3 are export-grade; TEA2 is the
  restricted EU-police cipher.
- THE BACKDOOR (headline): TEA1 takes an 80-bit key but its key-load step
  compresses that key into a 32-bit register before the keystream generator runs.
  Effective strength is 32 bits — brute-forceable on a laptop. In the Midnight
  Blue reference, tea1_init_key_register() takes 10 key bytes and returns a
  32-bit register; that reduction IS the backdoor. Show that step, not a banner.
- Disclosure timeline (attribute to the researchers, do not editorialize):
  2023 TETRA:BURST (Meijer, Bokslag, Wetzels, USENIX Security 2023) — CVE-2022-
  24402 = the TEA1 80→32-bit reduction; CVE-2022-24401 = an air-interface
  keystream-reuse decryption oracle from unauthenticated broadcast network time.
  2025 2TETRA:2BURST (Black Hat USA 2025) — CVE-2025-52941 = an E2EE variant
  (algorithm id 135) with AES-128 reduced to ~56-bit effective entropy, plus
  replay/injection CVEs. Confirm each CVE and venue before it ships.
- The vendors frame the reduction as Wassenaar export compliance, not a
  "backdoor." Present both framings; let the 32-bit fact carry the argument.

## NEW DEMO BRIEF

repo name      : crypto-lab-export-grade
short name (H1): Export Grade
subtitle       : TETRA · TEA1 · Key Reduction
one-liner      : Watch TETRA's TEA1 crush an 80-bit key into 32 bits before it
                 ever encrypts — then brute-force it against the real cipher.
concept        : An 80-bit key is only as strong as the register it is loaded
                 into. Export "compliance" and a backdoor can be the exact same
                 line of code.
primitives/spec: TEA1 (ETSI TETRA air-interface encryption), reverse-engineered
                 by Midnight Blue; Dual_EC as the sibling deliberate-weakness lab.
--accent       : #ff6b7f   (assigned centrally — do not change here)
favicon        : 🚓
in scope       : Real TEA1 keystream (ported from the Apache-2.0 reference),
                 KAT-verified; the 80→32-bit key-load shown step by step; a live
                 brute-force over the 32-bit effective keyspace (reduced/toy range
                 for the browser); the export-compliance vs backdoor framing.
non-goals      : No TEA2 (restricted). No live network interception. No full
                 TETRA stack. No exploit code for deployed networks. Not a claim
                 that AES or modern radio crypto shares this flaw. The E2EE 56-bit
                 result is presented as reported, not re-derived here.

## §1.1 SCOPE

Three panes.
1. THE CIPHER — real TEA1 keystream generation from (frame number, key),
   KAT-verified against the reference vectors. Proves compliance before dissection.
2. THE REDUCTION (HEADLINE) — the key-load step: 80 key bits enter, a 32-bit
   register comes out, and the generator only ever sees 32 bits of entropy.
3. THE BREAK — a brute-force over the reduced keyspace recovering the key against
   the page's REAL TEA1, plus the export-vs-backdoor framing and the 2023/2025
   disclosure record.

## §1.2 SECURITY / CORRECTNESS INVARIANTS (beat features on conflict)

INV-1  TEA1 keystream matches the reference KAT: frame 0x11111111 with the
       all-zero key yields the pinned keystream (confirm the exact bytes from
       tests.c before pinning). Fixture-pinned.
INV-2  The reduction is executed and counted on screen: the page derives the
       32-bit register from the 80-bit key and states the effective bit-count as
       a computed value, not a prose claim.
INV-3  The brute-force recovers a key that reproduces the target keystream
       byte-for-byte against the same TEA1 used to produce it (reduced keyspace
       for tractability; the reduction is what makes even the full 32 bits the
       real story). No simulated search.
INV-4  MUTATION GATE (§4.1c/§4.1d): perturbing the key-load reduction or the core
       must make INV-1/INV-3 FAIL in CI.
INV-5  Every negative claim carries a §4.1d fixture — in particular "the standard
       tests still pass / the radio still works while the key is 32-bit," a
       verdict that reads as OK-AND-BROKEN.

## §1.3 ARCHITECTURE

ALGORITHM SOURCE (normative):
Port TEA1 from MidnightBlueLabs/TETRA_crypto (Apache-2.0): tea1.c + tea1.h, with
the KAT vectors in tests.c. Port line by line; it is C — port, don't transliterate.
Preserve LICENSE/attribution per Apache-2.0 (NOTICE + copyright retained). The
key-load reduction lives in the port of tea1_init_key_register; expose it as its
own inspectable function. INV-1 byte equality on the KAT is the acceptance test.

Modules: src/tea1/ (core + keyload isolated), src/attack/brute.ts (isolated,
marked broken), src/ui/. The brute-force runs in a Web Worker so the UI stays
responsive; report progress. Client-side, no backend.

## §1.4 UI

PANE 1 — The Cipher
  Enter a key + frame number; generate keystream; KAT badge against the pinned
  vector. Plain-language intro ("what TETRA is, what export-grade means") first.
PANE 2 — The Reduction (HEADLINE)
  Animate the 80-bit key entering the load step and a 32-bit register emerging;
  a live "effective key strength: 32 bits" readout computed from the register
  width, beside the nominal "80 bits." SHOW the funnel; don't narrate it.
PANE 3 — The Break + The Record
  a. Brute-force: pick a short known-plaintext, run the worker, recover the key,
     verify it reproduces the keystream against real TEA1. A meter over the
     reduced keyspace makes the 2^32 tractability visceral.
  b. Framing: the vendor/Wassenaar "export compliance" statement and the
     researchers' backdoor characterization, side by side, dated and sourced.
  c. The 2025 E2EE 56-bit result as reported context (not re-derived).

REAL-WORLD box: police, military and critical-infrastructure radio in 100+
countries (add H1 to REAL_WORLD_TITLES). Sibling: crypto-lab-corrupted-oracle
(Dual_EC) — grep to confirm it exists before linking.

HERO — three roles distinct:
  subtitle    : spec label only
  description : real TEA1 with its key crushed to 32 bits, then brute-forced
  why it matters: an "80-bit" cipher can be 32-bit by design and still ship

## §1.5 VISUAL SEMANTICS

green = KAT matches.  alarm = recovered key / OK-AND-BROKEN verdict (never green
success).  funnel/red = the reduction step.  Icon+text+color; no decorative
motion; never draw the key as 80 bits where the generator uses 32.

## §1.6 EDGE CASES

- IV/frame-number expansion (tea1_expand_iv) must match the reference exactly.
- Brute-force with an all-zero or too-short known-plaintext: warn, don't produce
  a false-positive key.
- Worker cancellation mid-search: clean stop, no stale verdict.
- Keyspace size the browser can actually finish: cap and label the reduced range;
  do not claim a full 2^32 sweep the page did not run.

## §1.7 EXTENSION SEAMS

- TEA3 (the other export cipher) as a comparison toggle. Mark // [extension].
- The CVE-2022-24401 keystream-reuse oracle as a second attack pane.
- A "which TEA is on which network" jurisdiction map.

## VERIFY BEFORE WRITING COPY — do not assert, grep

- grep CATEGORIES; propose from {ATTACKS | ENCRYPTION}. Do not state a category
  is new.
- grep the catalog for existing export-control / deliberate-weakness / radio
  coverage and report overlaps before any "first"/"only" phrasing.
- grep for crypto-lab-tetra-* / crypto-lab-export-* name collisions before
  creating.
- Confirm the TEA1 KAT bytes from tests.c, the tea1_init_key_register reduction,
  and each CVE/venue from the disclosures before they ship.

## CI GATES (existing mechanisms — reference, do not reinvent)

- e2e/claims.spec.ts — §4.1b cross-checks (page keystream vs pinned KAT; recovered
  key re-derives keystream), §4.1c mutation discipline, §4.1d the OK-AND-BROKEN
  negative claim.
- §4 axe/WCAG gate (the worker progress UI is the a11y risk — live-region it).
- §5 README. §6.1/6.2 dependabot + deploy dispatch.
- §4.1d: no CLAIMS.yaml / THREAT-MODEL.md / second-language verifier.

## CITATIONS (verify each against the primary source before it ships)

- MidnightBlueLabs/TETRA_crypto (Apache-2.0) — tea1.c/.h, tests.c KAT vectors.
- Meijer, Bokslag, Wetzels, "All cops are broadcasting: TETRA under scrutiny,"
  USENIX Security 2023; CVE-2022-24401, CVE-2022-24402.
- 2TETRA:2BURST, Black Hat USA 2025; CVE-2025-52940/-52941/-52942/-52944.
- ETSI TETRA air-interface encryption (TEA family) — for naming/scope only.
- FIPS/Wassenaar export-control framing — for the vendor-statement side.