# CARAF-Knowledge-Base

CARAF Knowledge Base is a self-service library based on the Crypto Agility Risk Assessment Framework (CARAF) tailored for organizations seeking to evaluate the risk of PQC to their assets, understand where to start with migration, prioritize their assets for PQC migration, and receive technical guidance or resources to enable the PQC migration. Crypto agility refers to the ability to replace existing crypto primitives, algorithms, or protocols quickly, inexpensively, and with minimal risk of exposure and business overhead. Transitioning from one crypto solution to another can be time-consuming and expose organizations to unnecessary security risks. Therefore, CARAF can help organizations perform risk-based assessment and determine appropriate mitigation strategies tailored to their risk tolerance.

The current version (v1.0) focuses on risks/changes due to Post-Quantum Cryptography (PQC) migration. National Security Memorandum 10 (NSM-10) established the year 2035 as the primary target for completing the migration to PQC across Federal systems. However, cryptographic transition can take 10-20 years. PQC transition is expected to be a more complex endeavor due to the uncertainties and unknowns in quantum computing advancements, significant differences between PQC algorithms and classical algorithms, as well as limited crypto agility across existing systems. This knowledge base serves as a starting point that enables individuals or organizations at different levels of expertise to develope a PQC migration roadmap tailored to their needs. It provides:
- A standardized playbook for PQC migration from a risk assessment perspective
- Up-to-date guidance from standard bodies, industries, and vendors
- Educational resources on PQC and crypto agility, including real-world applications

# Who can benefit?
- Organizations and enterprises looking to prioritize their assets for PQC migration.
- Managers/leaders who want to evaluate the risk of PQC to their assets and where to start with migration.
- Developers looking for technical guidance or resources to enable the PQC migration.
- Security, hardware, software, and network professionals looking for basic educational resources on application of crypto agility and PQC.
  
# How do I use it?
 To start, please follow the instructions in each phase from 1 to 5:
- **[Phase 1](https://github.com/cma184_comcast/CARAF-Knowledge-Base/tree/main/Phase%201%3A%20Identify%20Threats): Identify Threats.** This is the starting point where the user will evaluate what assets are within scope of PQC migration. Once a list of assets within scope is created, proceed to Phase 2.
- **[Phase 2](https://github.com/cma184_comcast/CARAF-Knowledge-Base/tree/main/Phase%202%3A%20Inventory%20of%20Assets): Inventory of Assets.** This is where the user will evaluate and quantify the crypto agility of the assets based on details of the assets and implementation of crypto components. Once the detail of the assets and their crypto components are collected, with crypto agility score calculated, proceed to phase 3.
- **[Phase 3](https://github.com/cma184_comcast/CARAF-Knowledge-Base/tree/main/Phase%203%3A%20Risk%20Estimation): Risk Estimation.** This is where the user will evaluate and quantify the risk for the assets based on timeline and cost to mitigate. Once the risk is calculated, proceed to phase 4.
- **[Phase 4](https://github.com/cma184_comcast/CARAF-Knowledge-Base/tree/main/Phase%204%3A%20Secure%20Assets): Secure Assets.** Based on crypto agility score from Phase 2 and risk score from Phase 3, a migration option is recommended. After drafting up a list of actions necessary for the migration option of your choice, proceed to phase 5.
- **[Phase 5](https://github.com/cma184_comcast/CARAF-Knowledge-Base/tree/main/Phase%205%3A%20Organizational%20Roadmap): Organizational Roadmap.** Based on information from the previous phases, a roadmap is produced with a list of processes that will need to be changed to accomodate the PQC migration.

Each phase includes a folder with links to resources and tools to help you carry out actions relevant to that phase, should you prefer a more detailed or tailored variation than the basic CARAF calculation.
By the end of the 5 phases, the user will have a tailor-made migration strategy with description of the factor that constitutes risk or crypto agility, different ways to mitigate or manage the said factor, tools/resources to utilize, and example use cases. For examples of how it has been used, please refer to the use case folder.


# Original Paper
Chujiao Ma, Luis Colon, Joe Dera, Bahman Rashidi, Vaibhav Garg, CARAF: Crypto Agility Risk Assessment Framework, Journal of Cybersecurity, Volume 7, Issue 1, 2021, tyab013, https://doi.org/10.1093/cybsec/tyab013
