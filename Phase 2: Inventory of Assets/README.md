# Phase 2: Inventory of Assets
Once the threat vector driving crypto agility is determined, the next step is to inventory impacted assets. These assets refer to systems with independent crypto components that support either confidentiality, integrity, or availability. The specific scope will be determined by the organization and their use case. For large enterprises, the number of impacted assets may be too large to address simultaneously. Assets can then be categorized and prioritized according to the nature of the assets and the expected security risk exposure. Thus, an IoT ecosystem with two smart light bulbs and a central hub can be simultaneously described as three distinct assets or one single asset.

This phase evaluates the assets, especially the crypto components, to quantify the crypto agility aspect of the assets. In order to conduct the risk assessment, please collect the following information about the assets from [Phase 1](https://github.com/comcast-spider/CARAF-Knowledge-Base/tree/main/Phase%201%3A%20Identify%20Threats):

## Informational
- What is the lifespan of the asset (in years)? Value = $X$
- What is the time needed to migrate the asset (in years)? Value = $Y$,
$X$, and $Y$ will be used in the next phase: [Phase 3](https://github.com/comcast-spider/CARAF-Knowledge-Base/tree/main/Phase%203%3A%20Risk%20Estimation).

## _Required_ to be crypto agile
- Is it owned/managed by a third party? If no, +1.
- Are there dependencies that also need to be updated in case of crypto migration? If no, +1.
- Does implementation of it include hardware components (e.g., HSM, ASIC, FPGA, hardware accelerators, etc.)? If no, +1.
- Is it configured/managed by a third party? If no, +1.
- Does updating the crypto require changes to the asset? If no, +1.

## _Good-to-have_ to be more crypto agile
- *Does it use certificates with lifespan beyond 2035? If no, +1.
- *Does it store secret keys? If no, +1.
- *Does it contain encrypted data with lifespan beyond 2035? If no, +1.
- *Is it capable of remote updates? If yes, +1.
- *Is it capable of migrating to PQC algorithms?
  - Are there PQC implementations, tools, or services available? If yes, +1.
  - Is the asset capable of supporting the PQC key sizes and message sizes? If yes, +1.

Sum up the values from all questions for a combined crypto agility score ranging from 0 to 11. For the asset, if the answer is yes to any of the questions in the _Required_ section, it will be difficult to update the crypto component without significantly affecting the function of the asset; thus, the crypto agility score is _low_ (range from 0 to 5). The questions in _Good-to-have_ section does affect crypto agility, but may or may not be applicable depending on the type of asset; thus, the crypto agility score is _high_ (range from 6-11).

Once a crypto agility score is calculated for each asset, please proceed to [Phase 3](https://github.com/comcast-spider/CARAF-Knowledge-Base/tree/main/Phase%203%3A%20Risk%20Estimation).
