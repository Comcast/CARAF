# Phase 2: Risk Estimation (Updated)

This phase estimates the PQC-related risk level of an asset by evaluating **time-based exposure**, **data confidentiality requirements**, and **cost/effort of PQC migration**.  
The revised model improves accuracy by aligning with NIST recommendations, enforcing realistic migration timelines, and preventing misclassification of high-risk assets.

## Time to Exposure (Revised Model)

This step uses the updated **Exposure Index** instead of the previous `X + Y > Z` rule.

The following inputs are used:

- **X — Asset Lifespan** (automatically adjusted; see below)  
- **Data Retention Lifetime** — *new mandatory input*  
- **Y — Migration Lead Time**  
- **Z — Threat Horizon** (standardized presets)

### 1. Data Retention Lifetime (New Mandatory Input)

Many assets store or process long-lived data requiring confidentiality for **10–25+ years**.

To avoid underestimating exposure, **X** is recalculated as: X = max(Asset Lifespan, Data Retention Lifetime)

This ensures the model reflects the true confidentiality window.


### 2. Migration Lead Time (Y) — Minimum Enforcement

Realistic migration time is required due to dependencies on:

- Library upgrades  
- PKI transitions  
- Vendor support cycles  
- Firmware/embedded updates  
- Performance and interoperability testing  

To prevent unrealistic entries (e.g., `Y = 0`), the following **minimum thresholds** apply:

- **Software systems:** ≥ 0.5 years  
- **PKI, hardware, HSM, embedded systems:** ≥ 1–3 years  

The workbook warns users when `Y = 0` or values below minimum thresholds are entered.


### 3. Threat Horizon (Z) — Standardized Presets

To avoid overly optimistic or inconsistent predictions, predefined Z values are provided:

- **Conservative:** Z = 5  
- **Moderate:** Z = 7  
- **Standard:** Z = 10  

Users may override these values, but deviations are highlighted.

### 4. Exposure Index Calculation

The updated Exposure formula: Exposure = (DataRetention + MigrationLeadTime) – ThreatHorizon
E = (X + Y) – Z

This reflects when an asset becomes cryptographically unsafe relative to expected quantum-threat timelines.


### 5. Exposure Classification

| Exposure Value        | Classification | Meaning                                                             |
|-----------------------|----------------|---------------------------------------------------------------------|
| **Exposure ≥ 0**      | **EXPOSED**    | Asset will become vulnerable before migration completes.            |
| **-3 < Exposure < 0** | **AT RISK**    | Asset approaches vulnerability; migration planning required.        |
| **Exposure ≤ -3**     | **PHASE-OUT**  | Asset retires before the threat horizon; lower migration urgency.   |

Workbook safeguards also flag cases such as **DataRetention > Z**, indicating unavoidable high risk.

---

## Cost to Migrate

Cost factors still influence final risk severity. The following questions evaluate migration effort:

- Will performance overhead affect asset function?  
- Will updating to new PQC algorithms introduce recurring cost (hardware vs software)?  
- Is decrypt-and-re-encrypt required for long-lived data?  
- Will additional internal resources or vendor negotiations be required?

---

## Overall Risk Estimate

Risk is determined by combining the **Exposure classification** with **cost-to-migrate impact**.

### **High Risk**
- Exposure ≥ 0 **or**
- Asset is **AT RISK** *and* any cost-to-migrate question is answered *“yes”*

### **Low Risk**
- Asset is **PHASE-OUT** *and* migration cost impact is minimal

This ensures assets are no longer incorrectly classified as low-risk due to underestimated X or Y values.


Once the risk level is determined for each asset, proceed to [Phase 3](../CARAF%20Phases/Phase%203%3A%20Migration%20Recommendation.md).
