# LLM Support Bot — Cost & Dependency Audit Findings

Audit scope: Weave trace/cost observability and runtime dependency security posture (pydantic, jinja2, cryptography).

## 1. Weave trace results (Weights & Biases Weave)

**Team entity checked:** `hezil6643-modelbest`

**Projects found in the team account (20):** `simulated_env_tau2`, `breakfast-and-learn`, `weather-watch`, `platform-ops`, `genai-ops-review`, `payments-review`, `platform-review`, `investment-committee`, `breakfast-kit-launch`, `teaching-lab`, `weekly-notes`, `retro-reunion`, `sequence-models-onboarding`, `model-sourcing`, `inkwell-launch`, `model-audits`, `delivery-pilot-brief`, `tokyo-onsite-evaluation`, `orchid-7-handover`, `demo-api-readiness`, `team-offsite`

### Results

- **Traces found: 0.** Every one of the 20 projects was queried and every one returned zero traces (verified with both the trace count and the full trace/cost query, with cost data requested). No project in the team account holds the support bot's traces.
- **Most expensive trace by total cost:** not determinable — with zero traces there is no trace cost data, no per-trace cost, and no cost-by-model breakdown.
- **Token usage:** total tokens 0; input 0; output 0; average tokens per trace 0.
- **Status summary:** success 0 / error 0 / other 0.

### Finding — instrumentation gap (report upward)

The account has projects, but **the project holding the support bot's traces either does not exist in this account or contains no traces**. The support bot is not instrumented (or its traces are not being logged to this W&B team account). Consequences:

- Cost per trace and the most expensive traces are currently **unmeasurable**.
- No token accounting or model-mix data is available for cost attribution.
- This is an observability gap, not a cost finding: we cannot currently answer leadership's cost questions from Weave data.

**Recommended next step:** instrument the support bot with Weave tracing (or confirm/correct the W&B entity + project where its traces are logged) and re-run this audit once traces exist.

## 2. Dependency audit

Advisory data sourced from the GitHub Advisory Database (pip ecosystem). Release data from each library's upstream GitHub repository.

| Library | Upstream repo | Latest release | Advisory count | Highest severity |
|---|---|---|---|---|
| pydantic | pydantic/pydantic | `v2.14.1` | 2 | medium |
| jinja2 | pallets/jinja | `3.1.6` | 10 | high |
| cryptography | pyca/cryptography | `50.0.2` | 22 | high |

### 2.1 pydantic

**Latest release:** `v2.14.1` (published 2026-10-11) — https://github.com/pydantic/pydantic/releases/tag/v2.14.1

Advisories found (2):

- **GHSA-mr82-8j83-vxmv / CVE-2024-3772** — *medium* — "Pydantic regular expression denial of service". ReDoS in Pydantic < 2.4.0 and < 1.10.13 allows remote attackers to cause denial of service via a crafted email string. First patched: 2.4.0 / 1.10.13. CVSS 5.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H), CWE-1333.
- **GHSA-5jqp-qgf6-3pvh / CVE-2021-29510** — *medium* — "Use of 'infinity' as an input to datetime and date fields causes infinite loop in pydantic". Passing `infinity`, `inf` or `float('inf')` (or their negatives) to datetime or date fields causes validation to run forever with 100% CPU usage. First patched: 1.6.2 / 1.7.4 / 1.8.2. CVSS 3.3, CWE-835.

No high or critical advisories found for this package.

### 2.2 jinja2

**Latest release:** `3.1.6` (published 2025-03-05) — https://github.com/pallets/jinja/releases/tag/3.1.6

> **Note:** jinja2 was retired from the support bot's runtime stack. It is kept in this audit record for completeness. Its upgrade sub-issue was detached from the tracking parent and closed as not planned.

Advisories found (10):

High severity (3):

- **GHSA-8r7q-cvjq-x353 / CVE-2014-1402** — "Incorrect Privilege Assignment in Jinja2". `bccache.FileSystemBytecodeCache` default config in Jinja2 before 2.7.2 does not properly create temporary files, allowing local users to gain privileges via a crafted `.cache` file with a name starting with `__jinja2_` in `/tmp`. First patched: 2.7.2. CVSS 8.4, CWE-266.
- **GHSA-462w-v97r-4m45 / CVE-2019-10906** — "Jinja2 sandbox escape via string formatting". In Pallets Jinja before 2.10.1, `str.format_map` allows a sandbox escape. First patched: 2.10.1. CVSS 8.6, CWE-693.
- **GHSA-hj2j-77xm-mc5v / CVE-2016-10745** — "Jinja2 sandbox escape vulnerability". In Pallets Jinja before 2.8.1, `str.format` allows a sandbox escape. First patched: 2.8.1. CVSS 8.6, CWE-134.

Medium severity (7):

- **GHSA-cpwx-vrp4-4pq7 / CVE-2025-27516** — Jinja2 vulnerable to sandbox breakout through `|attr` filter selecting format method. First patched: 3.1.6.
- **GHSA-q2x7-8rv6-6q7h / CVE-2024-56326** — Jinja has a sandbox breakout through indirect reference to format method. First patched: 3.1.5.
- **GHSA-gmj6-6f8f-6699 / CVE-2024-56201** — Jinja has a sandbox breakout through malicious filenames. First patched: 3.1.5.
- **GHSA-h75v-3vvj-5mfj / CVE-2024-34064** — Jinja vulnerable to HTML attribute injection when passing user input as keys to the `xmlattr` filter. First patched: 3.1.4.
- **GHSA-h5c8-rqwp-cp95 / CVE-2024-22195** — Jinja vulnerable to HTML attribute injection via `xmlattr` filter keys containing spaces. First patched: 3.1.3.
- **GHSA-fqh9-2qgg-h84h / CVE-2014-0012** — Insecure Temporary File in Jinja2 (incomplete fix for CVE-2014-1402). First patched: 2.7.2.
- **GHSA-g3rq-g295-4j3m / CVE-2020-28493** — ReDoS in Jinja2 via the `urlize` filter. First patched: 2.11.3.

No low or critical advisories returned.

### 2.3 cryptography

**Latest release:** `50.0.2` (released 2026-09-30) — https://github.com/pyca/cryptography/releases/tag/50.0.2

> The pyca/cryptography repository publishes releases via git tags / PyPI rather than GitHub Release objects (the GitHub "latest release" endpoint returns 404 for this repo), so the newest release is the tag `50.0.2`, dated 2026-09-30 per the upstream changelog.

Advisories found (22):

High severity (9):

- **GHSA-6vqw-3v5j-54x4 / CVE-2024-26130** — NULL pointer dereference with `pkcs12.serialize_key_and_certificates` when called with a non-matching certificate and private key and an `hmac_hash` override. First patched: 42.0.4. CVSS 7.5, CWE-476.
- **GHSA-3ww4-gg4f-jr7f / CVE-2023-50782** — Vulnerable to a Bleichenbacher timing oracle attack (RSA key exchange decryption). First patched: 42.0.0. CVSS 7.5.
- **GHSA-cf7p-gm2m-833m / CVE-2023-38325** — Mishandles SSH certificates that have critical options. First patched: 41.0.2. CVSS 7.5, CWE-295.
- **GHSA-x4qr-2fvf-3mr5 / CVE-2023-0286** — Vulnerable OpenSSL included in cryptography wheels (type confusion, X.509). First patched: 39.0.1. CVSS 7.4, CWE-843.
- **GHSA-rhm9-p9w5-fwm7 / CVE-2020-36242** — Symmetrically encrypting large values can lead to integer overflow. First patched: 3.3.2. CVSS 9.1, CWE-190/787.
- **GHSA-hggm-jpg3-v476 / CVE-2020-25659** — RSA decryption vulnerable to Bleichenbacher timing vulnerabilities. First patched: 3.2. CVSS 5.9, CWE-385.
- **GHSA-q3cj-2r34-2cwc / CVE-2016-9243** — Improper input validation: HKDF returns an empty byte-string for lengths less than digest size. First patched: 1.5.3. CVSS 7.5, CWE-20.
- **GHSA-fcf9-3qw3-gxmj / CVE-2018-10903** — GCM tag forgery via `finalize_with_tag` not enforcing minimum tag length. First patched: 2.3. CVSS 7.5, CWE-20.
- **GHSA-jwv3-5hgf-82ww** — Duplicate self-signed intermediates can cause exponential path-building (resource exhaustion DoS). Severity high; no CVSS score recorded.

Medium severity (7):

- **GHSA-m2h6-j472-rp4c / CVE-2026-69248** — Verifier accepts wildcard DNS names allowing escape from permittedSubtrees. First patched: 49.0.0.
- **GHSA-p423-j2cm-9vmq / CVE-2026-39892** — Buffer overflow if non-contiguous buffers were passed to APIs (e.g. `Hash.update()`). First patched: 46.0.7.
- **GHSA-h4gh-qq45-vh27** — Vulnerable OpenSSL included in cryptography wheels (37.0.0–43.0.0). First patched: 43.0.1.
- **GHSA-9v9h-cgj8-h64p / CVE-2024-0727** — NULL pointer dereference in PKCS12 parsing (OpenSSL). First patched: 42.0.2.
- **GHSA-jfhm-5ghh-2f97 / CVE-2023-49083** — NULL-dereference when loading PKCS7 certificates. First patched: 41.0.6.
- **GHSA-w7pp-m8wf-vj6r / CVE-2023-23931** — `Cipher.update_into` can corrupt memory if passed an immutable Python object as the outbuf. First patched: 39.0.1.
- **GHSA-39hc-v87j-747x** — Vulnerable OpenSSL included in cryptography wheels (37.0.0–38.0.3). First patched: 38.0.3.

Low severity (5):

- **GHSA-m959-cc7f-wv43 / CVE-2026-34073** — Incomplete DNS name constraint enforcement on peer names. First patched: 46.0.6.
- **GHSA-79v4-65xg-pq4g / CVE-2024-12797** — Vulnerable OpenSSL included in cryptography wheels (42.0.0–44.0.0). First patched: 44.0.1.
- **GHSA-v8gr-m533-ghj9** — Vulnerable OpenSSL included in cryptography wheels (2.5–41.0.3). First patched: 41.0.4.
- **GHSA-jm77-qphf-c4w8** — Vulnerable OpenSSL included in cryptography wheels (0.8–41.0.2). First patched: 41.0.3.
- **GHSA-5cpq-8wj7-hf2v** — Vulnerable OpenSSL included in cryptography wheels (0.5–40.0.2). First patched: 41.0.0.

No critical advisories found. Note that many "vulnerable OpenSSL in wheels" advisories apply only when installing from PyPI wheels; sdist builds require managing your own OpenSSL.

## 3. Prioritisation of dependency work

Ordered by most severe advisory (critical > high > medium > low); libraries with no advisories rank last; ties keep the order pydantic, jinja2, cryptography.

| Rank | Library | Highest severity |
|---|---|---|
| 1 | jinja2 | high |
| 2 | cryptography | high |
| 3 | pydantic | medium |

After the jinja2 removal (retired from the stack), the active sub-issue order attached to the parent issue is: **cryptography, pydantic**.
