## 4. PQC Requirements


⬅ Back: [3. Third‑Party Categories Relevant to PQC](03-third-party-categories.md) · Next ➡: [5. Operationalizing PQC‑Aware Third‑Party Assurance](05-operationalization.md)

---
This section discusses PQC requirements that represent a unified set of PQC capabilities. Expectations for whether these capabilities must be planned or implemented depend on the applicable PQC migration phase, as described in the subsequent section.

<table>
  <thead>
    <tr>
      <th>Requirement</th>
      <th>Answer</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td colspan="2" align="center"><strong>Solution‑Specific</strong></td>
    </tr>
    <tr>
      <td>Uses TLS 1.3 with PQC support (planned or implemented)</td>
      <td>Yes / No</td>
    </tr>
    <tr>
      <td>Uses NIST FIPS 203 (ML‑KEM) for key exchange</td>
      <td>Yes / No</td>
    </tr>
    <tr>
      <td>Uses NIST FIPS 204, 205, or 206 for signatures</td>
      <td>Yes / No</td>
    </tr>
    <tr>
      <td>Uses NIST FIPS 197 (AES) for encryption</td>
      <td>Yes / No</td>
    </tr>
    <tr>
      <td colspan="2" align="center"><strong>Infrastructure‑Related</strong></td>
    </tr>
    <tr>
      <td>Maintains asset inventory to support PQC migration</td>
      <td>Yes / No</td>
    </tr>
    <tr>
      <td>Has internal risk assessment and prioritization processes for PQC migration</td>
      <td>Yes / No</td>
    </tr>
    <tr>
      <td>Has SDLC support for updating cryptographic libraries</td>
      <td>Yes / No</td>
    </tr>
    <tr>
      <td>Has PQC‑ready internal crypto infrastructure (e.g., PKI, HSM)</td>
      <td>Yes / No</td>
    </tr>
    <tr>
      <td>Has updated policies and controls to support PQC migration</td>
      <td>Yes / No</td>
    </tr>
    <tr>
      <td>Has begun deprecating RSA, ECDSA, ECDHE, and other classical algorithms</td>
      <td>Yes / No</td>
    </tr>
  </tbody>
</table>

These questions should be shared with prospective and existing third parties to support a comprehensive evaluation of PQC awareness, technical readiness, and organizational preparedness. If a third party answers **“Yes” to at least 6 out of the 10 questions**, this indicates a meaningful level of PQC awareness and preparation. However, further review by security and risk stakeholders remains necessary, and responses should be evaluated in conjunction with broader third‑party risk assessment considerations.

### Interpretation Across PQC Migration Phases
The PQC requirements listed above represent a unified and stable set of cryptographic capabilities that are relevant throughout the post‑quantum transition. These requirements are intentionally not bound to a single point in time. Instead, expectations for whether capabilities must be planned or implemented evolve as third parties progress through successive PQC migration phases. 

![](../../Figures/PQC%20Timeline.png)

The above figure depicts the timeline of the phases based on the [NIST PQC migration timeline](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf): the three phases have to happen **before the deadline to start deprecating classical cryptography by December 31, 2030 (i.e., they are considered deprecated starting in 2031)**. Next, we describe each of the phases and define how responses to the same set of requirements (as listed in the spreadsheet provided in the [Quickstart section](01-overview.md#quickstart)) are interpreted and what level of remediation is expected at each stage.

#### Phase 1 – Awareness & Planning (2026)
In this phase, “Yes” responses may indicate **planned, partial, or pilot adoption**. The objective is to establish PQC awareness, governance readiness, and intent. Third parties are expected to demonstrate planning activities, internal alignment, and roadmap development. Remediation focuses on providing documented PQC plans and timelines rather than technical implementation.

#### Phase 2 – Asset Inventory & Prioritization (2027-2028)
In this phase, requirements related to **asset inventory and prioritization** are expected to be **fully implemented**. Specifically, third parties should have:
- A maintained cryptographic asset inventory.
- An internal risk assessment and prioritization process for PQC migration.

Failure to demonstrate these foundational capabilities may warrant elevated (including Critical) risk findings, depending on the nature of the engagement and data processed. Other requirements may still be satisfied through documented plans, provided progress toward implementation is evident.

#### Phase 3 – PQC Integration (2029-2030)
In this phase, requirements related to **cryptographic algorithms, infrastructure, and deprecation of classical cryptography** are expected to be **implemented in production**. “Yes” responses should reflect actual deployment of PQC or hybrid cryptographic mechanisms. Continued reliance on classical algorithms without an executed migration path may result in Critical risk findings. Remediation expectations focus on completing PQC integration or, where applicable, planning for replacement or phase‑out of non‑compliant products or services.

Responses to the PQC requirements provide insight into a third party’s awareness, preparedness, and dependency risk related to PQC. However, responses do not, by themselves, guarantee PQC compatibility or long‑term cryptographic viability. Assessment outcomes are intended to support prioritization, escalation, and engagement decisions within the organization’s broader third‑party risk assessment programs.

---

⬅ Back: [3. Third‑Party Categories Relevant to PQC](03-third-party-categories.md) · Next ➡: [5. Operationalizing PQC‑Aware Third‑Party Assurance](05-operationalization.md)
