# Export Grade

## What It Is

Export Grade is a browser lab for the TEA1 air-interface stream cipher used by TETRA. It runs a TypeScript port of Midnight Blue's reverse-engineered TEA1, verifies it against the upstream known-answer tests, exposes the function that reduces a ten-byte key to one 32-bit register, and searches a labeled browser-sized part of that effective space. It then takes the rate that search measured on the learner's own machine and extrapolates it across larger keyspaces, and sets that cost beside the published cryptanalysis of full-round AES.

The cryptography and search are real. For tractability, the page selects the $2^{16}$ window containing its local fixture's register; it does not search all $2^{32}$ candidates. The page uses local fixtures rather than intercepted traffic. This is not production cryptography or an operational TETRA tool.

## Exhibits

1. **The Cipher** - enter an 80-bit key and frame number, run real TEA1, and compare the default result with the upstream KAT.
2. **The Reduction** - execute all ten rounds of `tea1_init_key_register`, inspect every S-box input and output, and watch 80 rendered input bits become a computed 32-bit register.
3. **The Break** - derive known keystream bytes from plaintext and ciphertext, search a $2^{16}$ window in a Web Worker, and independently verify the recovered register against the same TEA1 core.
4. **The Record** - compare TCCA's Wassenaar export-compliance explanation with Midnight Blue's intentional-weakness characterization, then follow the 2023 and 2025 disclosure record.
5. **The Wall** - read the candidates-per-second your own Exhibit 3 run measured, with the division visible, and extrapolate that one rate to $2^{32}$, $2^{40}$, $2^{56}$, $2^{80}$, $2^{128}$, and $2^{256}$ on a log2 scale. A scale-up control carries three editable multipliers, each labeled as your assumption rather than a fact, and the chart marks the keyspace your own machine clears in one second and in one year. Nothing renders until you have run Exhibit 3.
6. **Paper vs Practice** - thirteen published key-recovery attacks on *full-round* AES, each figure read from the cited paper's own summary table, plotted as log2 time against the $2^{128}$, $2^{192}$, and $2^{256}$ brute-force lines with data and memory beside it. The biclique results sit a couple of bits under the line; the related-key results sit far below it and require an attacker model no protocol supplies.

## When to Use It

Use this lab to teach effective key strength, inspectable key schedules, known-answer testing, how export policy can become cryptographic structure, or the difference between an attack that is faster than brute force and an attack anyone can finish.

Do **not** use it to assess a deployed network, intercept radio traffic, infer that AES shares TEA1's weakness, treat the browser's $2^{16}$ run as a completed $2^{32}$ search, or quote Exhibit 5's extrapolations as predictions of what real hardware costs.

## Live Demo

[Open Export Grade](https://systemslibrarian.github.io/crypto-lab-export-grade/).

Generate a TEA1 keystream, step through the complete key load, and recover the resulting working register without sending data to a backend.

## What Can Go Wrong

- An 80-bit input label does not provide 80-bit resistance when initialization compresses the key to 32 bits.
- A short known-keystream sample can create false positives, so the lab requires at least four bytes and verifies every recovered candidate byte-for-byte.
- An all-zero known-plaintext fixture can obscure what is plaintext, ciphertext, and keystream, so the UI rejects it.
- A browser cannot honestly claim to sweep all $2^{32}$ candidates interactively; the page labels its $2^{16}$ window and reports the exact number tested.
- A stale recovery is not evidence for changed inputs; changing the key, frame, or known plaintext retires the verdict.
- A rate measured once, in one browser, on one machine is not a cost model; Exhibit 5 labels every projected figure an extrapolation and refuses to render any of them until the learner's own run has produced a rate.
- A scale-up multiplier is an assumption, not a measurement, so Exhibit 5 makes all three editable, prints the one in force, and labels a multiplier past $10^{21}$ absurd instead of quietly computing it.
- A timer too coarse for a fast run makes a rate a lower bound, and a device below one candidate per second makes it a floor; both states say so rather than presenting a derived number as measured.
- "Broken" in a paper and "broken" on a radio are different events: the best published single-key attack on full AES is 2.49 bits faster than brute force, which is a result and not a threat.
- An attack model is part of the result, so every row names it; the related-key figures far below the brute-force line assume keys related by attacker-chosen differences, which a protocol does not hand out.
- Reduced-round cryptanalysis is a different measurement from full-round key recovery, so this lab plots only the latter and defers the round-count view to Iron Serpent.

## Real-World Usage

TETRA was standardized by ETSI in 1995 and is used in more than 100 countries for police, military, emergency-service, transport, industrial, and critical-infrastructure communications. TEA1 is one TETRA air-interface cipher. TCCA states that its effective key was reduced to 32 bits for Wassenaar export compliance; Midnight Blue calls the intentional reduction a backdoor.

The 2023 TETRA:BURST work by Carlo Meijer, Wouter Bokslag, and Jos Wetzels maps the TEA1 reduction to CVE-2022-24402 and the unauthenticated network-time keystream-reuse issue to CVE-2022-24401. Their 2025 2TETRA:2BURST work reports an E2EE algorithm-ID-135 variant with AES-128 traffic-key entropy reduced to 56 bits, associated by the researchers with CVE-2025-52941. As checked on 22 September 2026, the central 2025 CVE records remain reserved, so the page attributes those mappings rather than presenting them as finalized CVE descriptions.

## How to Run Locally

```bash
npm install
npm run dev
```

Vite serves the project under `/crypto-lab-export-grade/`. No backend or persistent storage is used.

## Related Demos

- [Corrupted Oracle](https://systemslibrarian.github.io/crypto-lab-corrupted-oracle/) - Dual_EC_DRBG and a different form of deliberate cryptographic weakness.
- [Iron Serpent](https://systemslibrarian.github.io/crypto-lab-iron-serpent/) - the round-count security-margin view of Serpent and AES. Exhibit 6 links out to it rather than restating it.
- [Grover](https://systemslibrarian.github.io/crypto-lab-grover/) - quantum search, which changes the exponent Exhibit 5 holds fixed. Exhibit 5 is classical only and does not model it.
- [AES Modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) and [Blind Oracle](https://systemslibrarian.github.io/crypto-lab-blind-oracle/) - the implementation and mode failures that break real systems whose block cipher is untouched.
- [Crypto Lab catalog](https://crypto-lab.systemslibrarian.dev/) - the full browser-demo collection.

## Build & Verify

```bash
npm test
npm run test:coverage
npm run build
npm run test:a11y
```

The suite contains **58 tests**: 33 Vitest unit tests and 25 Playwright browser tests. The unit suite pins both TEA1 vectors from Midnight Blue's `tests.c`, the rate and extrapolation arithmetic including its floors and its refusal to invent a rate, and the sourced attack table's citations and exponents, which it also cross-checks against the counts this README states in prose. The browser claims suite cross-checks the rendered KAT, computed 80-to-32 reduction, real worker recovery, cancellation, hidden panels, stale-verdict retirement, the measured rate re-derived from the two numbers the page prints, every extrapolated row recomputed from the page's own rate, the scale-up multiplier read back off the rendered durations, the absurd-multiplier label, and every plotted attack matched against its table row. The accessibility gate scans reachable desktop and 380px states - including Exhibit 5 inert, Exhibit 5 measured, each scale-up tier, and the attack table - with axe WCAG A/AA rules plus arithmetic text contrast, non-text contrast, reflow, focus, motion, and keyboard-scroller checks.

Measured unit coverage: **98.06% statements**, **95.38% branches**, **100% functions**, and **98.54% lines**.

Every row in `src/data/attacks.ts` was read from the primary paper's own summary table, and the file records which table. The claims suite fails if a row loses its citation or if a plotted bar stops matching its row.

The TEA1-derived files retain Midnight Blue's copyright and Apache-2.0 notice. See [NOTICE](NOTICE) and [THIRD_PARTY_LICENSES/Apache-2.0.txt](THIRD_PARTY_LICENSES/Apache-2.0.txt). The rest of the lab is MIT licensed.

## Performance

The default target sits 10,044 candidates into its $2^{16}$ window and completed in about 0.9 seconds on the development machine. Runtime varies by browser and hardware. Search work runs in a Web Worker, reports progress, and supports cancellation without leaving a stale verdict.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*