# Phase 1: Crypto Agility Measurement
This phase measures the crypto agility of the asset by asking the following binary and quantifiable questions.

## Informational
- What is the lifespan of the asset (in years)? Value = $X$
- What is the time needed to migrate the asset (in years)? Value = $Y$;
$X$ and $Y$ will be used in [Phase 2](../CARAF%20Phases/Phase%202%3A%20Risk%20Estimation.md).

## _Required_ to be crypto agile
- Is it owned by a third party? If no, +1.
- Is it configured/managed by a third party? If no, +1.
- Are there dependencies that also need to be updated in case of crypto migration? If no, +1.
- Does implementation of it include hardware components (e.g., HSM, ASIC, FPGA, hardware accelerators, etc.)? If no, +1.
- Does updating the crypto require changes to the asset? If no, +1.

## _Good-to-have_ to be more crypto agile
- *Does it use certificates with lifespan beyond 2035? If no, +1.
- *Does it store secret keys? If no, +1.
- *Does it contain encrypted data with lifespan beyond 2035? If no, +1.
- *Is it capable of remote updates? If yes, +1.
- *Are there PQC implementations, tools, or services available to help with the migration? If yes, +1.
- *Is the asset capable of supporting the PQC key sizes and message sizes? If yes, +1.

Next, sum up the values from all questions for a combined crypto agility score ranging from 0 to 11. For the asset, if the answer is yes to any of the questions in the _Required_ section, it will be difficult to update the crypto component without significantly affecting the function of the asset. On the other hand, the questions in _Good-to-have_ section does affect crypto agility, but may or may not be applicable depending on the type of asset. The final score determines the crypto agility as given below:
- *Low Agility*: range from 0 to 5.
- *High Agility*: range from 6 to 11.

Once a crypto agility score is calculated for each asset, please proceed to [Phase 2](../CARAF%20Phases/Phase%202%3A%20Risk%20Estimation.md).
