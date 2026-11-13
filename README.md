# Security Advisories — Nicholas Mullenski

![Published advisories](https://img.shields.io/badge/advisories-2-0a7bbb?style=flat-square)
![Vendors](https://img.shields.io/badge/vendors-Microsoft%20%C2%B7%20esaqa-444?style=flat-square)
![Classes](https://img.shields.io/badge/CWE-863%20%C2%B7%20200%2F203-8a1f1f?style=flat-square)
![Disclosure](https://img.shields.io/badge/disclosure-coordinated%20%2890--day%29-2ea043?style=flat-square)
![License](https://img.shields.io/badge/docs-CC%20BY%204.0-blue?style=flat-square)
![Code](https://img.shields.io/badge/PoC-MIT-informational?style=flat-square)

Public vulnerability advisories, root-cause write-ups, and reproducible proofs-of-concept for issues
I have discovered and reported through coordinated disclosure — found by reading source and tracing
authorization and dataflow boundaries, not by scanners.

**Researcher:** Nicholas Mullenski · [`@R00t3dbyFa17h`](https://github.com/R00t3dbyFa17h) · `K70n0s510`
**Focus:** source-code audit and dataflow analysis of authorization boundaries, access control, and injection sinks.

> Only **publicly disclosed** findings appear here. Each one was reported to the vendor first and is
> published after a fix shipped and any embargo lapsed. See [SECURITY.md](SECURITY.md) for the disclosure policy.

---

## Findings

`2 published` · `2 vendors` · `CWE-863 · CWE-200/203`

| ID | Vendor / Product | Type (CWE) | Severity (CVSS v3.1) | Impact | Discovery | Status | Date | Links |
|----|------------------|-----------|----------------------|--------|-----------|--------|------|-------|
| [CVE-2026-128970](advisories/CVE-2026-128970) | esaqa — **Psono Server** (CE & EE) | Incorrect Authorization (CWE-863) | **5.4 Medium** | Invitee without accepted membership deletes a group's share-rights, revoking access for all members | Source audit — create/delete authorization diff | **Fixed** (7.5.1) · credited | 2026-10-13 | [Advisory](advisories/CVE-2026-128970) · [CVE](https://www.cve.org/CVERecord?id=CVE-2026-128970) · [GHSA](https://github.com/advisories/GHSA-6r6m-8qp2-f3cm) · [Fix](https://gitlab.com/esaqa/psono/psono-server/-/commit/86e7ce7fdbb04fc4ae3430cc434179630948d48d) |
| [GHSA-4532-fhjf-wq2q](advisories/GHSA-4532-fhjf-wq2q) | Microsoft — **Agent Framework** (.NET) | Protected-value sensitivity bypass (CWE-200 / CWE-203) | **6.5 Moderate** | Declarative-workflow author launders an `Env` secret past the sink guard via a branch condition | Source audit — mitigation-bypass of GHSA-9f26 | **Fixed** (1.26.0) · credited | 2026-10-23 | [Advisory](advisories/GHSA-4532-fhjf-wq2q) · [GHSA](https://github.com/microsoft/agent-framework/security/advisories/GHSA-4532-fhjf-wq2q) · [Fix PR](https://github.com/microsoft/agent-framework/pull/9357) |

A machine-readable version of this list is in [`pedigree.csv`](pedigree.csv).

---

## Repository layout

```
security-advisories/
├── README.md                     # this index
├── SECURITY.md                   # coordinated-disclosure policy + contact
├── security.txt                  # RFC 9116 contact record
├── pedigree.csv                  # machine-readable findings list
├── LICENSE                       # CC BY 4.0 (write-ups) / MIT (PoC code) — see file
└── advisories/
    ├── CVE-2026-128970/          # Psono Server — group share-right deletion
    │   ├── README.md             # advisory
    │   ├── WRITEUP.md            # long-form technical write-up
    │   ├── images/               # diagrams
    │   └── poc/                  # local, fabricated-data reproducer
    └── GHSA-4532-fhjf-wq2q/      # Microsoft Agent Framework — ConditionGroup sensitivity bypass
        ├── README.md             # advisory
        ├── WRITEUP.md            # long-form technical write-up
        ├── images/               # diagrams
        └── poc/                  # .NET reproducer against published 1.24.0
```

---

## Disclosure

All findings here were reported privately to the vendor and are published only after remediation.
I follow a coordinated-disclosure model with a 90-day default deadline. Full policy and contact in
[SECURITY.md](SECURITY.md).

## License

Write-ups and documentation are licensed **CC BY 4.0**; proof-of-concept source code is licensed **MIT**.
See [LICENSE](LICENSE). PoCs are provided for defensive research and verification against patched
software; use only against systems you own or are authorized to test.
