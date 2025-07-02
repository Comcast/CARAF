# Reading Materials
## Cryptography Basics
- “Introduction to Modern Cryptography” by Jonathan Katz and Yehuda Lindell. (Book)
- "Cryptography I" by Dan Boneh, (Online course) https://www.coursera.org/learn/crypto

## PQC Basics
- Cloudflare Blog: What is Post-Quantum Cryptography? https://www.cloudflare.com/learning/ssl/quantum/what-is-post-quantum-cryptography/
- IBM: What is Quantum-Safe Cryptography? https://www.ibm.com/think/topics/quantum-safe-cryptography
-	Chujiao Ma, Luis Colon, Joe Dera, Bahman Rashidi, Vaibhav Garg. CARAF: Crypto Agility Risk Assessment Framework. Journal of Cybersecurity. https://academic.oup.com/cybersecurity/article/7/1/tyab013/6289827
-	Chujiao Ma and Vaibhav Garg. Navigating the Transition to a Post-Quantum World. SCTE Cable-Tech Expo. https://www.nctatechnicalpapers.com/Paper/2021/2021-navigating-the-transition-to-a-post-quantum-world
-	Implications of Entropy on Symmetric Key Encryption Resilience to Quantum. ATIS. https://atis.org/resources/implications-of-entropy-on-symmetric-key-encryption-resilience-to-quantum/
- Post-Quantum Cryptography by Daniel J. Bernstein, Johannes Buchmann, and Erik Dahmen. (Book)
- Quantum Safe Crypto by IBM (Online course): https://learning.quantum.ibm.com/course/practical-introduction-to-quantum-safe-cryptography
- ETSI White Paper: Quantum-Safe Cryptography and Security https://www.etsi.org/images/files/ETSIWhitePapers/QuantumSafeWhitepaper.pdf
- IETF PQC for Engineers: https://www.ietf.org/archive/id/draft-ietf-pquip-pqc-engineers-06.html
- IETF PQC Migration Use Cases: https://www.ietf.org/archive/id/draft-vaira-pquip-pqc-use-cases-02.html

## Government Policies on PQC
- USA (NIST) https://csrc.nist.gov/news/2022/pqc-candidates-to-be-standardized-and-round-4
- USA (CNSA) https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/1/CSI_CNSA_2.0_FAQ_.PDF
- UK https://www.ncsc.gov.uk/whitepaper/next-steps-preparing-for-post-quantum-cryptography
- Canada https://www.cyber.gc.ca/en/news-events/nist-announces-post-quantum-cryptography-selections
- Germany https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile&v=7
- Netherlands https://www.ncsc.nl/binaries/ncsc/documenten/publicaties/2022/juli/guidelines-for-quantum-safe-transport-layer-encryption/guidelines-for-quantum-safe-transport-layer-encryption/Guidelines_for_PQC_-_Kyber.pdf
- France https://cyber.gouv.fr/sites/default/files/document/follow_up_position_paper_on_post_quantum_cryptography.pdf
- Saudi Arabia https://nca.gov.sa/ar/ncs_en.pdf
- European Commission https://digital-strategy.ec.europa.eu/en/library/recommendation-coordinated-implementation-roadmap-transition-post-quantum-cryptography
- Australia https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/ism/cyber-security-guidelines/guidelines-cryptography
- Norway https://nsm.no/getfile.php/133478-1591960609/NSM/Filer/Dokumenter/NSM%20cryptographic%20recommendations.pdf

## Asset Inventory
- Cryptography Bill of Material (CBoM), similar to Software Bill of Material (SBoM): https://github.com/CycloneDX/guides/blob/main/CBOM/en/0x10-Introduction.md
- Crypto Agility Maturity Model with different factors that contribute to crypto agility, it may be useful for those looking for a more fine-grained way to quantify crypto agility beyond questions from this knowledge base: https://camm.h-da.io/model/

## Crypto Agility & Risk Estimation
- Mosca's Theorem: https://cdn.prod.website-files.com/63ef0996726f31b9968ba679/648c8e28cfee25748915738f_a-methodology-for-quantum-risk-assessment-pdf.pdf
- Quantum threat timeline report: https://globalriskinstitute.org/publication/2024-quantum-threat-timeline-report/

## Libraries & Tools
- OpenSSL 3.5 with PQC support: https://openssl-corporation.org/post/2025-04-08-openssl-35-final-release/
- C library for prototyping/experimenting with quantum-resistant algorithms: https://github.com/open-quantum-safe/liboqs
- Pquip WG looking at PQC in protocols: https://datatracker.ietf.org/wg/pquip/about/ 
- LM-KEM for embedded microcontrollers: https://github.com/pq-code-package/mlkem-c-embedded

## PQC Migration Guidelines
-	[Organizational Migration to Quantum-Safe Cryptography](https://quantum-safe.ca/wp-content/uploads/2022/11/Migrating-to-quantum-safe-cryptography_final.pdf) – A Curriculum Guide, by Quantum-Safe Canada
-	[Guidelines For Quantum Risk Management For Telco](https://www.gsma.com/get-involved/working-groups/wp-content/uploads/2023/09/Guidelines-for-Quantum-Risk-Management-for-Telco-v1.0.pdf), by Global System for Mobile Communication (GSMA)
-	[Risk Model Technical Paper](https://www.fsisac.com/hubfs/Knowledge/PQC/RiskModel.pdf), from Post-Quantum Cryptography Working Group by FS-ISAC, which protects global financial system
-	[Special Publication, Migration to Post-Quantum Cryptography](https://csrc.nist.gov/pubs/sp/1800/38/iprd-(1)), by National Institute of Standards and Technology (NIST) 
-	[Strategic Framework for Crypto Agility and Quantum Risk Assessment](https://atis.org/resources/strategic-framework-for-crypto-agility-and-quantum-risk-assessment/), by Alliance for Telecommunications Industry Solutions (ATIS) 
-	[Quantum Safe Technology – Managing Risks and Opportunities for Quantum Safe Development](https://www.ncs.co/dam/jcr:81bb243e-0cdd-4c04-92e2-d110c01fa0e8/IBM_NCS_Quantum_Security_v1.0.pdf), in collaboration between IBM and NCS, a prominent digital and technology service provider in the Asia-Pacific region.
-	[Strategic Framework for Crypto Agility and Quantum Risk Assessment](https://atis.org/resources/strategic-framework-for-crypto-agility-and-quantum-risk-assessment/). ATIS. 
-	Jayati Dev. [Standards with Open Questions regarding PQC Adoption. MITRE Post-Quantum Cryptography Coalition](https://pqcc.org/standards-with-open-questions-regarding-pqc-adoption/)
-	Jayati Dev, Vaibhav Garg. [Transitioning to Quantum-Safe Cryptography: Exploring the Role and Value for Developing and Implementing a Cryptographic Bill of Materials](https://pqcc.org/transitioning-to-quantum-safe-cryptography-exploring-the-role-and-value-for-developing-and-implementing-a-cryptographic-bill-of-materials/). MITRE Post-Quantum Cryptography Coalition. 
-	[CFDIR Migration guide (intro to hybrid and example questions to vendors)](https://ised-isde.canada.ca/site/spectrum-management-telecommunications/sites/default/files/attachments/2023/cfdir-quantum-readiness-best-practices-v03.pdf): Available via CFDIR 
