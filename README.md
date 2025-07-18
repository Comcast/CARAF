# Crypto Agility Risk Assessment Framework (CARAF)

With the rise of quantum computing, [classical cryptographic algorithms like RSA are no longer adequate to protect our data](https://www.nist.gov/news-events/news/2023/08/nist-standardize-encryption-algorithms-can-resist-attack-quantum-computers). Hence, organizations must update their computing assets that use any classical cryptographic algorithms to then use the [new post-quantum cryptography (PQC) algorithms](https://csrc.nist.gov/projects/post-quantum-cryptography), namely perform a migration on the assets' cryptographic algorithms from classical into PQC (i.e., PQC migration).

![](Figures/CARAF%20Flow%20Diagram.png)

The Crypto Agility Risk Assessment Framework (CARAF) helps organizations evaluate the risks of their assets in the context of post-quantum cryptography (PQC) migration. We start from **Phase 0** that involves creating an inventory of all computing assets using cryptographic algorithms: this becomes the input to CARAF (see ① above). For each asset, CARAF assesses *crypto agility* – how easily the asset can transition to PQC, and *risk level* – the asset’s importance and need for PQC protection. CARAF includes three phases to guide migration decisions for each asset – click the links below to explore each phase:
- **[Phase 1](CARAF%20Phases/Phase%201%3A%20Crypto%20Agility%20Measurement.md): Crypto Agility Measurement.** In this phase, CARAF uses binary and numerical questions to evaluate an asset’s crypto agility based on its cryptographic components.
- **[Phase 2](CARAF%20Phases/Phase%202%3A%20Risk%20Estimation.md): Risk Estimation.** In this phase, CARAF also provides another set of binary and numerical questions to estimate the risk level for the asset.
- **[Phase 3](CARAF%20Phases/Phase%203%3A%20Migration%20Recommendation.md): Migration Recommendation.** Based on crypto agility and risk estimate scores from phases 1 and 2, CARAF provides a migration recommendation for each asset: *migrate*, *phase out*, or *accept risk*.

At the output of [Phase 3](CARAF%20Phases/Phase%203%3A%20Migration%20Recommendation.md), CARAF will add a migration recommendation for every asset in the list (see ② above). Based on the recommendation, actions differ depending on whether the asset is first-party or third-party (see ③ above).

# Quickstart with CARAF Calculator
We have created a [CARAF calculator](Resources/CARAF%20Calculator.xlsm) (you can download the raw file as an Excel sheet) that performs the risk assessment on each asset in an asset inventory. Please review [CARAF phases](CARAF%20Phases) before using the calculator. Then, watch the video below to get started.

https://github.com/user-attachments/assets/4bf38dee-8ace-43a4-8df2-70798ca745d6

# CARAF is Referenced by Government and Industry

![](Figures/Referencing%20Organizations.png)

- **NIST:** [Migration to Post-Quantum Cryptography Quantum Readiness: Cryptographic Discovery](https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38b-preliminary-draft.pdf)
- **CSCC:** [The Engineer Who Cried Quantum](https://www.comms-scc.org/wp-content/uploads/2023/08/The-Engineer-Who-Cried-Quantum2.pdf)
- **ATIS:** [Strategic Framework for Crypto Agility and Quantum Risk Assessment](https://atis.org/resources/strategic-framework-for-crypto-agility-and-quantum-risk-assessment/)
- **NCS/IBM:** [Managing Risks and Opportunities for Quantum Safe Development](https://www.ncs.co/dam/jcr:81bb243e-0cdd-4c04-92e2-d110c01fa0e8/IBM_NCS_Quantum_Security_v1.0.pdf)
- **GSMA:** [Guidelines for Quantum Risk Management for Telco](https://www.gsma.com/get-involved/working-groups/gsma_resources/guidelines-for-quantum-risk-management-for-telco/)
- **FSISAC:** [Preparing for a Post-Quantum World by Managing Cryptographic Risk](https://www.fsisac.com/hubfs/Knowledge/PQC/PreparingForAPostQuantumWorldByManagingCryptographicRisk.pdf)
- **NCTA:** [Understanding Quantum-Safe Timelines and Deployments](https://www.nctatechnicalpapers.com/Paper/2023/3591_Pala_5298_paper/download)

# Contribution
We welcome all kinds of contributions to this repository! Please have a look at [CONTRIBUTING.md](CONTRIBUTING.md) for further information and guidelines.

# Maintainers
The list of maintainers of this GitHub repository is available in [MAINTAINERS.md](MAINTAINERS.md). Please consider becoming a maintainer! 😃

# Roadmap
Roadmap information is available in [ROADMAP.md](ROADMAP.md).
  
# Publication
Chujiao Ma, Luis Colon, Joe Dera, Bahman Rashidi, Vaibhav Garg, [CARAF: Crypto Agility Risk Assessment Framework, Journal of Cybersecurity, Volume 7, Issue 1, 2021](https://doi.org/10.1093/cybsec/tyab013).

More reading materials on PQC are available [here](Reading%20Materials/README.md).
