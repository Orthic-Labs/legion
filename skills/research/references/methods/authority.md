# Method — authority

Loaded when `ResearchRoute.methods` contains `authority`. Primary use: verifying
official positions (government, regulator, court, standards body) for legal/medical/
technical claims.

## Mechanics

- Search restricted to authoritative domains: `.gov`, `.gov.in`, `europa.eu`,
  regulator portals (FDA, EMA, CDSCO, SEC, MCA, RBI), court websites, ISO/IEC/BS
  portals.
- Authority records populate the legal evidence model with `authority_type`,
  `forum`, `precedential_status`, `negative_treatment`, and `current_as_of`.
- A search snippet alone never counts as evidence. The official document must be
  opened and the passage located (A2 fencing).
