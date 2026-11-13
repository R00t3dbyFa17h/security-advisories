# Security & Coordinated Disclosure Policy

This repository publishes vulnerability research **after** coordinated disclosure. It is not a place to
report vulnerabilities in third-party products — report those to the affected vendor.

## How I disclose

For issues I discover and report to vendors, I follow a coordinated-disclosure model:

1. **Report privately** to the vendor (security contact, VDP, bug-bounty platform, or GitHub Security Advisory).
2. **Coordinate** on a fix and, where applicable, a CVE/GHSA identifier and credit.
3. **Publish** here only after a fix has shipped and any embargo has lapsed.
4. **Default deadline:** 90 days from the initial report, after which details may be published regardless
   of fix status, unless a longer timeline has been mutually agreed. This mirrors the industry-standard
   norm used by Google Project Zero and similar programs.

Every advisory in this repository lists its own disclosure timeline.

## Scope of proof-of-concept code

Proof-of-concept code is published for **defensive** purposes: to let defenders, maintainers, and other
researchers reproduce and verify a finding against already-patched software. PoCs use fabricated data and
local lab setups. Do not run them against systems you do not own or are not explicitly authorized to test.

## Contact

- **GitHub:** [@R00t3dbyFa17h](https://github.com/R00t3dbyFa17h) — open an issue for corrections, or use
  GitHub private vulnerability reporting if you need to reach me confidentially about content here.
- A PGP key and dedicated security address can be added on request.

> Note: contact details intentionally avoid publishing a personal email address. Reach out via GitHub
> and I will follow up through an appropriate channel.
