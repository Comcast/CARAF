# Phase 2: Risk Estimation
This phase estimates the risk level of the asset, representing the value and importance of the asset to be secured with PQC algorithms. Here, we calculate the risk level by considering time and cost.

## Time to exposure
Mosca's theorem is used as reference:
- Lifespan of the asset is $X$ from [Phase 1](../CARAF%20Phases/Phase%201:%20Crypto%20Agility%20Measurement.md).
- Time needed for migration is $Y$ from [Phase 1](../CARAF%20Phases/Phase%201:%20Crypto%20Agility%20Measurement.md).
- Time before threat results in a compromise (now - 2035) is $Z$.
- Calculate the value of $Z - (X+Y)$.
  - If the result is positive, your asset will be *phased out* before PQC migration is required.
  - If the result is negative, your asset will be *vulnerable* for $Z - (X+Y)$ number of years.

## Cost to migrate
The evaluation will be based on the following factors:
1. Will performance overhead be critical to the function of the asset? For example, the answer may be yes for streaming application, or no for databases accessed once per month.
2. Will there be a significant cost for updating to the new algorithms each time? For example, the answer may be yes if asset is implemented in hardware, or no if asset is implemented in software.
3. *Is decrypting then re-encrypting the asset needed (e.g., long-lived data)?
4. *Will there be a cost to migrate to PQC (i.e., additional internal resources dedicated to migration or negotiation with new vendors)?
The questions with * are a one-time cost. 

Based on the answers to the above questions, there are two levels of risk estimate:
- *High risk*: If your asset will be *vulnerable* timeline-wise and you answered yes to item 1 or 2 above for cost, risk = high.
- *Low risk*: Otherwise, risk = low.

Once the risk level is determined for each asset, proceed to [Phase 3](../CARAF%20Phases/Phase%203%3A%20Migration%20Recommendation.md).
