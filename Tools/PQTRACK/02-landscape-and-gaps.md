## 2. Current Landscape & PQC Gaps

⬅ Back: [1. Overview](01-overview.md) · Next ➡: [3. Third‑Party Categories Relevant to PQC](03-third-party-categories.md)

---
Across large enterprises, particularly in the telecommunications sector, third‑party risk assessment programs typically follow a multi‑stage lifecycle to scope, assess, and manage risk throughout a third‑party engagement. While terminology varies, the underlying structure is broadly consistent across the industry.

![](../../Figures/Third-Party%20Risk%20Assessment.png)

As shown in the above diagram, this lifecycle generally includes:
- **Initial risk scoping and data classification (1 and 2)**, used to determine engagement criticality, data exposure, and inherent risk.
- **In-depth risk assessment (3)**, where security, privacy, and compliance controls are evaluated in more depth based on scoped risk.
- **Enhanced or continuous oversight for critical third parties (4)**, as an escalation path for high‑impact, long‑lived, or systemically important relationships.

These practices are effective for managing classical security and privacy risks and are typically operationalized through existing mechanisms such as criticality ratings, severity ranking, escalation paths, vendor communications, and exception handling.

### Gaps in Traditional Third‑Party Security Assurance for PQC

While traditional third‑party risk assessment programs are effective for managing classical security and privacy risks, PQC introduces challenges that are not fully addressed by existing models. In particular, two structural gaps are commonly observed across the industry:

- **Cryptographic solution providers are often out of scope or under‑scoped**: Third parties that provide cryptographic solutions (e.g., PKI services, HSM platforms, key management systems, or cryptographic libraries) may not directly process or store customer or enterprise data. As a result, data‑centric risk scoping approaches may exclude these third parties from deeper assessment, despite the fact that they produce long‑lived cryptographic trust anchors whose compromise or obsolescence would have systemic impact in a post‑quantum context.

- **Cryptography is assessed as a static control rather than a long‑term dependency**: Existing assessments typically verify the presence of encryption or key management controls, but do not evaluate cryptographic agility, asset inventory, prioritization, or readiness for migration to PQC algorithms. Forward‑looking cryptographic dependencies (e.g., algorithm lifetimes, deprecation planning, and PQC adoption readiness) are therefore rarely evaluated explicitly during risk scoping or assessment.

### PQTRACK Enhancements

To address these gaps without replacing existing third‑party assurance frameworks, PQTRACK introduces two targeted enhancements that integrate naturally into current operating models:

- [**Cryptography‑aware scoping categories**](03-third-party-categories.md), distinguishing third parties that *produce cryptographic trust anchors*, *consume cryptographic trust anchors*, or primarily *process data*, enabling more accurate identification of long‑lived post‑quantum dependencies.

- [**A focused set of PQC‑specific in-depth risk assessment questions**](04-pqc-requirements.md), designed to evaluate cryptographic awareness, asset tracking, prioritization, and readiness for adoption of NIST‑standardized PQC algorithms, rather than simply confirming the presence of encryption.

PQTRACK complements existing third‑party risk scoping, assessment, and continuous monitoring processes by adding cryptography‑specific structure and forward‑looking context, while continuing to rely on established governance, escalation, and exception‑handling mechanisms.

---

⬅ Back: [1. Overview](01-overview.md) · Next ➡: [3. Third‑Party Categories Relevant to PQC](03-third-party-categories.md)
