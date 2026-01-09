# Phase 2: Risk Estimation (Updated)

This phase estimates the risk level of the asset, representing the value and importance of the asset to be secured with PQC algorithms. Here, we calculate the risk level by considering time, data retention, and cost.

## Time to exposure
We use Mosca's theorem as a start and add data retention as an additional factor. Further, we view data as part of the asset:
- Lifespan of the asset is $X$ from [Phase 1](../CARAF%20Phases/Phase%201:%20Crypto%20Agility%20Measurement.md).
- Time needed for migration is $Y$ from [Phase 1](../CARAF%20Phases/Phase%201:%20Crypto%20Agility%20Measurement.md).
- Data retention is $D$.
- Time before threat results in a compromise is $Z$. Per [NIST IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf), there are two milestones that can serve as the $Z$ value:
  - *End of 2030*: Classical algorithms are deprecated after 2030.
  - *End of 2035*: Classical algorithms are disallowed after 2035.
- While the original Mosca's theorem computes the value of $Z - (X+Y)$, we, instead, compute $Z - (max(X,D)+Y)$.
  - If the result is positive, your asset will be *phased out* before PQC migration is required.
  - If the result is negative, your asset will be *vulnerable* for $Z - (max(X,D)+Y)$ number of years.
- $X$, $Y$, $Z$, and $D$ are non-zero values representing a certain amount of time.

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
