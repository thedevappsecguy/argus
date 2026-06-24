---
name: owasp-risk-rating
description: OWASP Risk Rating Methodology. Always loaded so the agent scores each threat's likelihood/impact factors deterministically.
---
# OWASP Risk Rating Methodology

**When to use:** always — loaded for every system so the enumeration/rating agent assigns
each threat an OWASP risk score. `Risk = Likelihood × Impact`.

**How to use:** for every proposed threat, assign a 0–9 score to each factor below, grounded
in a specific piece of model evidence (an actor's privilege, an element's exposure, the data
classification it handles, an existing control). You assign the **factor scores**; the
factor→severity mapping is **deterministic** (computed by `argus.risk.rate`), so the same
factor scores always produce the same severity. Do not output the final severity yourself.

## Likelihood factors (0–9, higher = more likely)
- **ease_of_discovery** — how easily an attacker finds the issue. Internet-exposed / reachable
  from an anon actor → high (7–9); deep internal, no untrusted path → low (1–3).
- **ease_of_exploit** — effort/skill to exploit. Unauthenticated, well-known technique → high;
  needs privileged position or chained steps → low.
- **awareness** — how well-known this class of flaw is (catalog/OWASP Top 10 issues → high).
- **intrusion_detection** — scored **inversely** to detection strength: no logging/alerting on
  the path → high (7–9); active monitoring / WAF / anomaly detection → low (1–3).

## Impact factors (0–9, higher = worse) — calibrate by data classification
- **loss_of_confidentiality** — sensitivity/volume of data exposed. PII/PCI/PHI/secrets → high.
- **loss_of_integrity** — how corrupted/forged the data could be.
- **non_compliance** — regulatory exposure (PCI-DSS, HIPAA/PHI, GDPR) if the threat is realized.
- **privacy_violation** — extent of personal-data privacy harm.

## Deterministic mapping (do not compute the severity yourself)
1. Average the 4 likelihood factors and the 4 impact factors separately.
2. Band each average: `0–<3 = LOW`, `3–<6 = MEDIUM`, `≥6 = HIGH`.
3. OWASP overall-severity matrix `(likelihood_level, impact_level) → severity`:

| Likelihood＼Impact | LOW | MEDIUM | HIGH |
|---|---|---|---|
| **LOW** | Note | Low | Medium |
| **MEDIUM** | Low | Medium | High |
| **HIGH** | Medium | High | Critical |

**Worked example:** an unauthenticated, internet-reachable endpoint returning PHI →
likelihood factors ~{9,8,7,7} (avg 7.75 → HIGH), impact factors ~{9,5,8,8} (avg 7.5 → HIGH)
→ **Critical**.

Source: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
