## 3. Third‑Party Categories Relevant to PQC

⬅ Back: [2. Current Landscape & PQC Gaps](02-landscape-and-gaps.md) · Next ➡: [4. PQC Requirements](04-pqc-requirements.md)

---
When providing a technology‑related product or service to an organization, third parties may be required to migrate their offerings to support PQC. Not all third parties use cryptography in the same way; therefore, they are classified based on the **criticality of their cryptographic functions and dependencies**.

<table>
  <thead>
    <tr>
      <th width="30%">Category</th>
      <th width="35%">Definition</th>
      <th width="35%">Sub-category</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="4"><strong>Critical Crypto Infrastructure Third Parties</strong></td>
      <td rowspan="4">
        These third parties provide a <em>trust anchor</em> (core cryptographic services).
      </td>
      <td>
        <strong>Identity &amp; Trust Management</strong>
        <ul>
          <li>Public Key Infrastructure (PKI)</li>
          <li>Single Sign-On (SSO)</li>
          <li>Identity &amp; Access Management (IAM)</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>
        <strong>Key Management &amp; Protection</strong>
        <ul>
          <li>Key Management Service (KMS)</li>
          <li>Hardware Security Module (HSM)</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>
        <strong>Secure Boot &amp; Attestation</strong>
        <ul>
          <li>Trusted Platform Module (TPM)</li>
          <li>Secure Element (SE)</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>
        <strong>Cryptographic Libraries</strong>
        <ul>
          <li>SSL / TLS</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td rowspan="4"><strong>Crypto-Dependent Platform Third Parties</strong></td>
      <td rowspan="4">
        These third parties consume trust anchors and apply cryptographic operations in platforms.
      </td>
      <td>
        <strong>Cloud Platform</strong>
        <ul>
          <li>Compute resources</li>
          <li>Cloud storage services</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>
        <strong>Operating System (OS) Image</strong>
        <ul>
          <li>Hardened operating system</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>
        <strong>IoT Devices</strong>
        <ul>
          <li>Systems-on-Chip (SoC)</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td>
        <strong>Middleware &amp; Runtime</strong>
        <ul>
          <li>Container runtime environment</li>
          <li>Virtual Machine (VM)</li>
        </ul>
      </td>
    </tr>
    <tr>
      <td rowspan="1"><strong>Data Processing Third Parties</strong></td>
      <td rowspan="1">
        These third parties store and/or transmit data.
      </td>
      <td>
        <strong>Data Storage &amp; Transmission Services</strong>
        <ul>
          <li>Data storage services</li>
          <li>Data transmission services</li>
        </ul>
      </td>
    </tr>
  </tbody>
</table>

If a third party falls into one of the identified cryptographic dependency categories and the engagement is expected to extend beyond 2030, the PQC requirements outlined below should be shared as part of the inherent in-depth risk assessment and incorporated into the organization’s third‑party risk assessment workflows.

---

⬅ Back: [2. Current Landscape & PQC Gaps](02-landscape-and-gaps.md) · Next ➡: [4. PQC Requirements](04-pqc-requirements.md)
