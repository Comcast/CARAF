# Phase 3: Risk Estimation
This phase evaluates and quantifies the risk to the assets if no countermeasures are taken for the threat. Lack of information about incidents is particularly challenging in the context of crypto agility as the goal is to model the risk of an event that has not yet materialized. Thus, the risk here is calculated with combination of the time and cost. A more crypto agile asset will be less expensive to migrate and therefore pose overall lower risk. Therefore, crypto agility risk is a function of the time to exposure and the cost to migrate.

## Time to exposure
Mosca's theorem is used as reference:
- Lifespan of the asset is $X$ from [Phase 2](https://github.com/comcast-spider/CARAF-Knowledge-Base/tree/main/Phase%202%3A%20Inventory%20of%20Assets).
- Time needed for mitigation is $Y$ from [Phase 2](https://github.com/comcast-spider/CARAF-Knowledge-Base/tree/main/Phase%202%3A%20Inventory%20of%20Assets).
- Time before threat results in a compromise (2035) is $Z$.
- Calculate the value of $Z - (X+Y)$.
  - If the result is positive, your asset will be phased out before PQC migration is required
  - If the result is negative, your asset will be vulnerable for $Z - (X+Y)$ number of years

## Cost to migrate
The evaluation will be based on the following factors:
1. Will performance overhead be critical to the function of the asset? For example, the answer may be yes for streaming application, or no for databases accessed once per month.
2. Will there be a significant cost for updating to the new algorithms each time? For example, the answer may be yes if asset is implemented in hardware, or no if asset is implemented in software.
3. *Is decrypt then re-encrypt of the asset needed (e.g., long-lived data)?
4. *Will there be a cost to migrate to PQC (as in additional internal resources dedicated to migration or negotiation with new vendors)?

The questions with * are a one-time cost. If your asset will be vulnerable timeline-wise and you answered yes to item 1 or 2 above for cost, risk = high. Otherwise, risk = low.
Once the risk level is determined for each asset, proceed to [Phase 4](https://github.com/comcast-spider/CARAF-Knowledge-Base/tree/main/Phase%204%3A%20Secure%20Assets).
