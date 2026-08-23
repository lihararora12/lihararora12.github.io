---
title: "Metabase says its critical zero-day was actively exploited"
summary: "An unauthenticated SQL-injection path can lead to Metabase administrator access, exposed database credentials, and data theft."
advisoryDate: 2026-08-06
updatedAt: 2026-08-11
identifier: "CVE-2026-72898"
vendor: "Metabase"
product: "Metabase"
priority: "act-now"
status: "Active exploitation"
dueDate: 2026-08-14
kev: true
cwes: ["CWE-89"]
technologies: ["Analytics", "Data platforms"]
weaknesses: ["SQL injection"]
impacts: ["Admin takeover", "Credential exposure", "Data exposure"]
evidence: ["Vendor-confirmed exploitation", "CISA KEV"]
actions: ["Patch", "Investigate", "Rotate credentials"]
eli5: "Imagine a dashboard with a forgotten side door. A stranger can slide database instructions through that door, promote themselves to building manager, then open the cupboards where connected database keys are stored."
flow:
  - label: "Reset endpoint"
    detail: "An unauthenticated attacker reaches /api/session/reset_password."
  - label: "SQL injection"
    detail: "The request runs attacker-controlled SQL against the Metabase application database."
  - label: "Admin access"
    detail: "Database changes can give the attacker administrator control of Metabase."
  - label: "Connected data"
    detail: "Stored database credentials and data reachable through Metabase may be exposed."
sourceLinks:
  - label: "Metabase security update"
    url: "https://www.metabase.com/blog/security-update"
  - label: "GitHub security advisory — GHSA-vwf4-m7j8-wcjf"
    url: "https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf"
  - label: "NVD — CVE-2026-72898"
    url: "https://nvd.nist.gov/vuln/detail/CVE-2026-72898"
  - label: "CISA KEV — CVE-2026-72898"
    url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-72898"
draft: false
---

## What happened

Metabase says its Cloud service was attacked through a previously unknown vulnerability affecting versions 1.58 and above. Metabase blocked the abused endpoint, identified the flaw, and patched its Cloud customers. The corresponding GitHub advisory rates the issue critical with a CVSS 3.1 score of 10.0 and confirms active exploitation. The issue is now tracked as CVE-2026-72898 as well as GHSA-vwf4-m7j8-wcjf.

CISA added CVE-2026-72898 to the Known Exploited Vulnerabilities catalog on August 11, 2026, with an August 14 required-action date for covered agencies.

Self-hosted installations are not patched automatically. An unauthenticated attacker can inject SQL into the Metabase application database, gain instance administrator access, change configuration, steal stored credentials for connected databases, query accessible data, and export it.

## What to do

Upgrade to at least the safe point release for your branch. The `0.x` releases are OSS; Enterprise Edition uses the corresponding `1.x` release:

- 0.58.24 / 1.58.24
- 0.59.21 / 1.59.21
- 0.60.17 / 1.60.17
- 0.61.11 / 1.61.11
- 0.62.9 / 1.62.9
- 0.63.5 / 1.63.5

Versions below 58 are not affected according to Metabase. If you cannot upgrade immediately, temporarily block `/api/session/reset_password`.

For an internet-accessible reset endpoint, Metabase also recommends that you:

1. Revoke active sessions by deleting rows from the `core_session` table.
2. Remove unrecognized API keys and review administrator accounts.
3. Rotate credentials for connected databases.
4. Review warehouse logs, Metabase activity, and query history for unauthorized behavior.

## What to look for

Metabase describes a likely compromise pattern as a `POST /api/session/reset_password` returning HTTP 400 followed by `GET /api/user/current` returning HTTP 200. If that sequence appears in application or ingress logs, treat the instance as likely compromised—not merely waiting for a patch.

## Management note

This is the rare vulnerability that saves everyone time by arriving with active exploitation, a 10.0 score, and a direct path to database credentials. Skip the scoring workshop. Patch, investigate, rotate, and verify.
