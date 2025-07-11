# Phase 3: Migration Recommendation
Based on the crypto agility and risk estimate for each asset, this phase will give an actionable recommendation for the asset to the organization performing the PQC migration. For each asset, there will be one of the following three recommendations:

- If the crypto agility is *high* and risk is *high*, the recommendation is to *migrate* the asset. It can be achieved by upgrading the asset with the new PQC algorithms.
- If the crypto agility is *low* and risk is *high*, the recommendation is to *phase out* the asset. This may mean that we replace the asset with a new one that supports PQC algorithms.
- Regardless of crypto agility, if the risk is *low*, the recommendation is to *accept the risk*. For this recommendation, the asset will be left unchanged.

Finally, the recommendation can be added to its corresponding asset in the list. The actions needed for each recommendation differ depending on the nature of the asset and the organization. 

## Migrate / Phase Out Recommendation
For *migrate* and *phase out* recommendations, the organization has one of the following action items:
- **Option 1 - Migration/phase-out for first-party asset:** First, the organization must gain a clear understanding of the engineering process required to migrate or phase out the asset. This can be achieved by reviewing the system specifications and adhering to the official PQC guidelines provided by the manufacturer. Additionally, artificial intelligence (AI) and large language models (LLMs) can be utilized to generate tailored migration recommendations based on the asset’s technical specifications. Further, as part of the migration, the organization should also perform a performance evaluation using a defined set of metrics to assess the overhead introduced by PQC algorithms, compared to the classical algorithms previously in use.
- **Option 2 - Vendor Risk Assessment (VRA) for third-party asset:** If the asset is owned and managed by a third-party vendor, the organization must conduct a VRA specifically focused on PQC considerations. Thereafter, the organization can work with the third-party vendor to plan and eventually perform the asset migration.

## Accept Recommendation
For *accept* recommendation, the organization does not have actionable items to perform on the asset itself. However, the organization can take certain actions like updating the organizational policy to allow the asset to not be migrated and still adopt older standards (i.e., FIPS).
