# Phase 2: Risk Estimation
This phase estimates the risk level of the asset, representing the value and importance of the asset to be secured with PQC algorithms. Here, we calculate the risk level by considering time, data retention, and cost.

## Time to exposure
We use Mosca's theorem as a start and add data retention as an additional factor. Further, we view data as part of the asset:
- Lifespan of the asset is $X$ from [Phase 1](../CARAF%20Phases/Phase%201:%20Crypto%20Agility%20Measurement.md).
- Time needed for migration is $Y$ from [Phase 1](../CARAF%20Phases/Phase%201:%20Crypto%20Agility%20Measurement.md).
- Data retention period is $D$ from [Phase 1](../CARAF%20Phases/Phase%201:%20Crypto%20Agility%20Measurement.md).
- Time before threat results in a compromise is $Z$. Per [NIST IR 8547](https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf), there are two milestones that can serve as the $Z$ value:
  - *End of 2030*: Classical algorithms are deprecated after 2030.
  - *End of 2035*: Classical algorithms are disallowed after 2035.
- While the original Mosca's theorem computes the value of $Z - (X+Y)$, we, instead, compute $Z - (max(X,D)+Y)$.
  - If the result is positive, your asset will be *phased out* before PQC migration is required.
  - If the result is negative, your asset will be *vulnerable* for $Z - (max(X,D)+Y)$ number of years.
- $X$, $Y$, $Z$, and $D$ are non-zero values representing a certain amount of time.

## Cost to migrate
The evaluation will be based on the following factors:
1. Will performance overhead be critical to the function of the asset? For example, the answer may be yes for streaming application, or no for databases accessed once per month.
2. Will there be a significant cost for updating to the new algorithms each time? For example, the answer may be yes if asset is implemented in hardware, or no if asset is implemented in software.
3. Is decrypting then re-encrypting the asset needed (e.g., long-lived data)?
4. Will there be a cost to migrate to PQC (i.e., additional internal resources dedicated to migration or negotiation with new vendors)?

Based on the answers to the above questions, there are two levels of risk estimate:
- *High risk*: If your asset will be *vulnerable* timeline-wise and you answered yes to any of the questions in the `Cost to migrate` section above, risk = high.
- *Low risk*: Otherwise, risk = low.

Once the risk level is determined for each asset, proceed to [Phase 3](../CARAF%20Phases/Phase%203%3A%20Migration%20Recommendation.md).
