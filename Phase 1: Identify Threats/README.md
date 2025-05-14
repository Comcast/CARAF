# Phase 1: Identify Threats
The first step is to identify the threat that a CARAF based assessment aims to address. The threat can be due to emerging technology, newly discovered vulnerabilities, or regulations. By identifying the threats before taking inventory of assets, the assets that will not be impacted by the threat in question can be discounted. For example, if assets are likely to be phased out before the need for crypto transition, they can be considered out of scope. Similarly, if the threat only impacts software assets, hardware assets can be considered out of scope. Assessors can then explicitly address assets that are impacted by the threat. This enables a more optimized and realistic assessment framework, especially, as organizations with a wide variety of assets and exhaustive inventories are rare.

This section will help to determine what assets are impacted by the threats due to PQC migration. Your assets are within scope of the assessment if they:
- Use public key encryption algorithms for digital signature (FIPS 186) and/or key establishment (SP800-56A).
- Have a lifespan beyond 2035 (the primary target for completing PQC migration across federal systems according to National Security Memorandum 10 (NSM-10)).
- Contain information susceptible to harvest-now-decrypt-later attacks.

Once a list of the assets within scope is created, proceed to [Phase 2: Inventory of Assets](https://github.com/cma184_comcast/CARAF-Knowledge-Base/tree/main/Phase%201%3A%20Identify%20Threats).
