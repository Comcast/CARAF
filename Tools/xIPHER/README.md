# xIPHER – Cryptographic Discovery Toolkit

xIPHER is a cryptographic discovery and compliance toolkit to inventory cryptographic assets, assess compliance with encryption standards, and enable Post-Quantum Cryptography (PQC) readiness across code, network, and infrastructure environments.

xIPHER provides end-to-end visibility into cryptographic usage across:

	• **Code**: Certificates, cryptographic libraries
	• **Network**: SSL/SSH/other protocols, certificates in traffic using network telemetry sources
	• **Infrastructure**: Third-party vendors, cloud services

## Versions & Features

**Current**:
xIPHER v1.0.1 (Code – Certificates) [https://github.com/Comcast/CARAF/tree/main/Tools/xIPHER/xIPHER_Certificate_Scanner] 

	• Detects certificates in code repositories on 
	• Validates compliance with encryption standards
	• Supports modification of list of encryption algorithms, Certificate Authority list, and customization in compliance tracking

**Upcoming**:
xIPHER v2.0 (Code – FLAIR) 

	• Detects cryptographic libraries, APIs, and keys in code
	• Language-agnostic approach (Python, C/C++ planned)

**Planned**:
xIPHER v2.1 (Network – SSH)

	• Detects SSH cryptographic configurations
	• Identifies weak keys and algorithm usage
	• Identifies PQC-compliant algorithms and non-compliance
  
## Standards & Interoperability
The open-source version also incorporates IETF draft standards for crypto discovery and inventory: 

- Cryptography Bill of Materials (CBoM) for PQC and aligns with CycloneDX
  [https://datatracker.ietf.org/doc/draft-dev-xipher-cbom-extension/] 
