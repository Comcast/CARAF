## Getting started

1. Open `PQBench.xlsm`. It is macro-enabled; when prompted, Enable Content / Enable Macros (macros drive sheet generation, the single-select rule, and the JSON export).
2. You'll land on the Assets sheet with three buttons.

## The sheets

* Assets — list your asset names in column A from row 2. Holds the three action buttons.
* Template — the master questionnaire layout that gets copied for each asset. Don't rename it.
* Reference (hidden) — the 19×19 category-to-metric mapping plus named ranges. Don't edit unless the canonical mapping in `Categories-vs-Metrics.md` changes.
* One sheet per asset — created from the Template by the macro; this is where you work.

## How to use it

1. List assets. On Assets, type one asset/deployment name per row in column A (starting row 2).
2. Generate sheets. Click Create Asset Sheets. One sheet is created per new asset (idempotent — existing sheets are left alone).
3. Set the platform. On each asset sheet, pick the target OS in B2 (`Ubuntu`, `RHEL`, or `Windows`). PQLab currently targets Ubuntu and RHEL; Windows is forward-looking.
4. Answer the questionnaire. In column C, rows 7–25, mark each subcategory `Yes`/`No`.
   * Single-select: within Energy, Computational, Security, and Cryptographic Implementation, only one subcategory can be `Yes` (setting one clears its siblings).
   * Under Network, you may pick one Latency option and one Throughput option — these are two independent axes.
5. Read the result. The Final Selected Metrics table (column A names, column B `Yes`/`No`) updates automatically with the union of metrics implied by your selections.
6. See the reasoning. Click Refresh Derivation Tables to draw a traceability grid to the right of the questionnaire (from column H): for each selected subcategory it shows which metrics it contributes (✅/❌) and the final union.
7. Export the handoff. Save the workbook first, then click Export PQLab JSON. It writes `pqbench_handoff.json` next to the workbook. Only assets with at least one `Yes` are included.

## The three buttons

* Create Asset Sheets — makes one questionnaire sheet per asset name on the Assets sheet.
* Refresh Derivation Tables — redraws the per-asset traceability grids.
* Export PQLab JSON — writes `pqbench_handoff.json` beside the workbook.

## Data model

Five categories / 19 subcategories / 19 metrics, transcribed from `Categories-vs-Metrics.md` (the source of truth):

* Energy Constraints: Very High, High, Moderate, Low, Minimal
* Network Performance: Latency (Low/Moderate/High) and Throughput (High/Moderate/Low)
* Computational Resources: High, Moderate, Low
* Security Requirements: High, Moderate, Minimum
* Cryptographic Implementation Method: Hardware-based, Software-based

## How metric selection works

Each metric in the Final Selected Metrics table uses one formula against the hidden mapping (`SubcatMatrix`) and the answers in `C7:C25`:

```
=IF(SUMPRODUCT(INDEX(SubcatMatrix,0,MATCH($A29,MetricList,0)),--($C$7:$C$25="Yes"))>0,"Yes","No")
```

A metric is selected if it applies to any selected subcategory (a union, not an intersection).

## The JSON handoff

Per answered asset the export contains: `name`, `platform`, `selected_subcategories[]` (`category` + `subcategory`), `applicable_metrics[]` (`name` + proposed `metric_id` + proposed `units`), and a derived `algorithm_scope` hint (`kem`/`signature`). The formal contract and the open questions for the PQLab team are in `Handoff-Schema.md` / `Resources/pqbench_handoff.schema.json`.
