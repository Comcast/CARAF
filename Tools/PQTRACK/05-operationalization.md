## 5. Operationalizing PQC‑Aware Third‑Party Risk Assessment


⬅ Back: [4. PQC Requirements](04-pqc-requirements.md) · Next ➡: [README](README.md)

---
PQC readiness is operationalized by extending existing third‑party risk assessment workflows to explicitly include **cryptographic dependency risk**, rather than relying solely on data‑centric scoping. This approach builds on current practices (e.g., criticality classification, severity ranking, escalation, third‑party engagement, and exception handling) without introducing parallel assessment processes.

### How Third Parties Are Typically Assessed Today

- In most third‑party security assurance programs, third parties are brought into scope for detailed risk assessment primarily when they:
  - Process, store, or transmit a defined amount of organizational or customer data, or
  - Are classified as critical based on business impact or service dependency.
- As a result, **data‑processing third parties** are typically subject to risk assessment, while **cryptographic solution providers** (e.g., PKI services, HSM platforms, cryptographic libraries) may remain out of scope or receive limited review if they do not directly process data.

### Expanded Scoping with PQTRACK

- PQTRACK extends existing scoping logic by introducing **cryptography‑aware third‑party categories**, as discussed in [Section 3 (Third‑Party Categories Relevant to PQC)](03-third-party-categories.md), ensuring that:
  - **Trust‑anchor providers** and **trust‑anchor consumers** are explicitly identified and brought into scope for PQC assessment, even if they do not directly process data.
  - **Data‑processing third parties** continue to be assessed, but are now also evaluated for **PQC readiness**.
- As a result, third parties that provide cryptographic solutions are no longer excluded from assessment due to data‑centric scoping alone.
- All third parties falling into the categories defined in [Section 3 (Third‑Party Categories Relevant to PQC)](03-third-party-categories.md) are required to respond to the **PQC requirements in [Section 4 (PQC Requirements)](04-pqc-requirements.md)**, regardless of whether they process data directly.

### Severity Ranking and Findings

- Responses to the PQC requirements are evaluated using existing **severity classification and escalation models**:
  - In **Phase 1**, lack of PQC awareness or planning (e.g., no PQC roadmap) typically results in *High‑severity* findings, with remediation focused on providing documented plans and timelines.
  - In **Phase 2**, failure to demonstrate foundational capabilities (e.g., cryptographic asset inventory or internal prioritization) may be escalated to *High‑severity* findings, particularly for high‑impact or long‑lived engagements, with remediation focused on building cryptographic asset inventory and executing internal prioritization.
  - In **Phase 3**, lack of implemented PQC support (e.g., continued reliance on classical cryptography without an executed migration path) may result in *High‑severity* findings requiring timely remediation (i.e., actual system migration into PQC algorithms).
- Critical findings trigger escalation into **enhanced or continuous third‑party oversight**, consistent with existing operational practices.

### Third‑Party Engagement, Remediation, and Exceptions

- PQC findings are communicated to third parties through **established third‑party governance channels**, using standard remediation tracking, escalation, and follow‑up mechanisms.
- Remediation expectations depend on the applicable PQC migration phase:
  - **Phase 1** emphasizes **plans and readiness**.
  - **Phases 2 and 3** require **demonstrable technical implementation**.
- Where immediate remediation is not feasible, organizations may rely on:
  - Time‑bound remediation plans with defined milestones
  - Third‑party PQC roadmaps aligned to industry and regulatory timelines
  - Contractual commitments or planned phase‑out strategies (e.g., third‑party decommissioning or service replacement)
- PQC‑related exceptions are handled through existing **risk acceptance and exemption frameworks**, documented and periodically reviewed as standards and third‑party capabilities evolve.

---

⬅ Back: [4. PQC Requirements](04-pqc-requirements.md) · Next ➡: [README](README.md)
