# Phase 1: Crypto Agility Measurement
This phase measures the crypto agility of the asset by asking the following binary and quantifiable questions.

## Informational
- What is the lifespan of the asset (in years)? Value = $X$
- What is the time needed to migrate the asset (in years)? Value = $Y$;
$X$ and $Y$ will be used in [Phase 2](../CARAF%20Phases/Phase%202%3A%20Risk%20Estimation.md).
- What is the lifespan of the data stored in the asset (in years)?

## Crypto Agility Related
- Is the asset owned by the first party? If yes, +1.
- Is the asset configured and managed by the first party? If yes, +1.
- Are there no dependencies that need updates during a cryptographic migration? If yes, +1.
- Does the implementation avoid hardware-specific components (e.g., HSM, ASIC, FPGA, hardware accelerators)? If yes, +1.
- Can cryptographic updates be applied without requiring changes to the asset itself? If yes, +1.
- Does the asset use certificates with a lifespan extending to at most 2035? If yes, +1.
- Does the asset store no secret keys? If yes, +1.
- Does the asset contain encrypted data with a lifespan extending to at most 2035? If yes, +1.
- Is the asset capable of receiving remote updates? If yes, +1.
- Are PQC implementations, tools, or services available to support migration for this asset? If yes, +1.
- Is the asset capable of supporting PQC key sizes and message sizes? If yes, +1.

Next, sum up the values from all questions for a combined crypto agility score ranging from 0 to 11. For the asset, if the answer is yes to any of the questions in the _Required_ section, it will be difficult to update the crypto component without significantly affecting the function of the asset. On the other hand, the questions in _Good-to-have_ section does affect crypto agility, but may or may not be applicable depending on the type of asset. The final score determines the crypto agility as given below:
- *Low Agility*: range from 0 to 5.
- *High Agility*: range from 6 to 11.

Once a crypto agility score is calculated for each asset, please proceed to [Phase 2](../CARAF%20Phases/Phase%202%3A%20Risk%20Estimation.md).
