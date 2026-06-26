# MAC derandomization

A Python toolkit for analyzing IEEE 802.11 Probe Request frames, evaluating device fingerprint properties, and running MAC address derandomization experiments. The project can load data from JSON or PCAP files, extract selected Information Element fields, compute information and privacy metrics, build distance matrices between MAC addresses, and cluster devices with OPTICS.

## Project scope

The project supports three main workflows:

1. **IE analysis** – analyzes value distributions for a selected field, including entropy, mutual information, stability, cardinality, and value-to-label relationships.
2. **Fingerprint analysis** – builds fingerprints from a selected set of fields and evaluates fingerprint anonymity.
3. **MAC derandomization** – computes distances between MAC addresses using field and weight configurations, performs clustering, and validates results against device labels.

## Directory structure

```text
MAC_derandomization/
├── .gitignore           # Git ignore rules, including Zone.Identifier metadata
├── README.md            # Project documentation
├── requirements.txt     # Python dependencies
├── configs/
│   ├── fields/          # YAML files with active field sets used in experiments
│   └── weights/         # JSON files with field-weight scenarios
├── dataset/             # small unit-test datasets derived from the Cagliari dataset
├── scripts/
│   ├── run_fingerprints.sh
│   ├── run_ie_analysis_all_fields.sh
│   ├── unit_tests.sh
│   └── utilities/       # helper scripts for counting, renaming, and PCAP utilities
├── src/
│   ├── cli/             # CLI entry points
│   ├── data_loaders/    # JSON and PCAP loaders
│   ├── derandomization/ # distance calculation, clustering, and evaluation
│   ├── fingerprint/     # fingerprint extraction
│   ├── metrics/         # statistical, information, and privacy metrics
│   └── visualization/   # plots and report generation
└── outputs/             # generated reports and figures
```

## Requirements

Recommended Python version: **3.10+**.

Install Python dependencies from the provided `requirements.txt`:

```bash
pip install -r requirements.txt
```

The current dependency list is:

```text
matplotlib
numpy
pyshark
PyYAML
scapy
scikit-learn
tabulate
tqdm
```

PCAP support also requires **Wireshark/TShark**, because `pyshark` uses the system `tshark` binary.

On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install tshark
```

Optional virtual environment setup:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Input data

The default data location is:

```text
dataset/
```

The included `dataset/` directory contains small unit-test datasets derived from the Cagliari dataset. These folders are intentionally not documented one by one, because they are test fixtures and may change over time.

The larger datasets referenced by batch scripts, such as:

```text
dataset/cagliari/
dataset/cagliari_HT/
dataset/awid3/
```

are expected to exist locally when running the full experiment scripts. They are not necessarily included in the repository or ZIP archive.

JSON input should contain a list of devices with a structure similar to:

```json
[
  {
    "MAC": "aa:bb:cc:dd:ee:ff",
    "LABEL": "device_1",
    "PROBE_REQs": [
      {
        "TIME": ["..."],
        "RSSI": ["..."],
        "DATA": {
          "HT_CAP_INFO": "...",
          "TAG_LIST": ["0", "1", "45"]
        }
      }
    ]
  }
]
```

PCAP input is loaded from dataset subdirectories. Labels can be inferred either from folder names or from files, depending on the selected CLI option.

## Field configuration

YAML files in `configs/fields/` define active fields for experiments.

Available field configuration files include:

```text
configs/fields/all_fields_ht_decomposed.yaml
configs/fields/all_field_ht_single_field.yaml
configs/fields/best_fields.yaml
configs/fields/worst_fields.yaml
```

Example:

```yaml
name: best_fields
description: "Fields selected as the strongest fingerprinting features."

active_fields:
  - HT_CAP_INFO
  - HT_AMPDU_PARMS
  - TAG_LIST
  - EXT_CAP
```

Commonly used fields include:

- `HT_CAP`
- `HT_CAP_INFO`
- `HT_AMPDU_PARMS`
- `HT_MCS_SET`
- `HT_EXT_CAP`
- `HT_Tx`
- `HT_ANTENNA`
- `TAG_LIST`
- `EXT_CAP`
- `DATA_RTS.SUPP`
- `DATA_RTS.EXT`
- `RSSI`
- `TIME`

Some internal distance configurations also support more complex field groups, such as `RSSI_TIME`, `EXT_TAG`, and `VENDOR_SPEC`.

## Weight configuration

JSON files in `configs/weights/` contain weight scenarios for derandomization experiments.

Available weight configuration files include:

```text
configs/weights/all_metrics_ht_decomposed.json
configs/weights/all_metrics_ht_single_field.json
configs/weights/baselines_ht_single_field.json
configs/weights/fingerprint_all_fields.json
configs/weights/fingerprint_best_fields.json
```

Example schema:

```json
[
  {
    "name": "scenario_name",
    "weights": {
      "HT_CAP_INFO": 1.0,
      "TAG_LIST": 0.5,
      "DATA_RTS.SUPP": 1.0
    }
  }
]
```

When using `--weights-file`, pass only the filename if the file is located in `configs/weights/`:

```bash
--weights-file fingerprint_best_fields.json
```

The code resolves this to:

```text
configs/weights/fingerprint_best_fields.json
```

If an absolute path is provided, it is used directly.

If `--weights-file` is not provided, the code runs a single scenario with default weights.

## Running IE analysis

For a single field:

```bash
python3 -m src.cli.ie_analysis \
  --input-dir cagliari_HT \
  --input-type pcap \
  --labeled \
  --label-from folder \
  --workers 8 \
  --field HT_CAP_INFO \
  --full-analysis
```

Batch IE analysis for all configured fields:

```bash
bash scripts/run_ie_analysis_all_fields.sh
```

The batch script currently uses:

```text
dataset/cagliari_HT/
```

as the input dataset.

## Running fingerprint analysis

Example:

```bash
python3 -m src.cli.fingerprints \
  --input-dir cagliari \
  --input-type pcap \
  --labeled \
  --label-from folder \
  --workers 8 \
  --fields HT_CAP_INFO HT_AMPDU_PARMS TAG_LIST EXT_CAP \
  --scenario cagliari_best_fields
```

Batch fingerprint analysis:

```bash
bash scripts/run_fingerprints.sh
```

The batch script currently runs fingerprint experiments for:

```text
dataset/cagliari/
dataset/awid3/
```

and reads field lists from YAML files in:

```text
configs/fields/
```

Results are written to:

```text
outputs/reports/
outputs/figures/
```

## Running derandomization

Example with field and weight configuration:

```bash
python3 -m src.cli.derandomize \
  --input-dir cagliari \
  --input-type pcap \
  --labeled \
  --label-from folder \
  --workers 8 \
  --scenario cagliari_derandomization \
  --fields-config-path configs/fields/best_fields.yaml \
  --weights-file fingerprint_best_fields.json \
  --scenario-workers 1
```

Without precomputation:

```bash
python3 -m src.cli.derandomize \
  --input-dir cagliari \
  --input-type pcap \
  --labeled \
  --label-from folder \
  --workers 8 \
  --scenario cagliari_derandomization \
  --fields-config-path configs/fields/best_fields.yaml \
  --weights-file fingerprint_best_fields.json \
  --scenario-workers 1 \
  --no-precompute
```

The `--no-precompute` mode uses the full distance calculation per scenario. Precomputation is faster, but it should be verified when working with fields whose distance contribution is not a simple linear single-weight component.

To verify precomputed distances against the full calculation for the first scenario:

```bash
python3 -m src.cli.derandomize \
  --input-dir cagliari \
  --input-type pcap \
  --labeled \
  --label-from folder \
  --workers 8 \
  --scenario cagliari_derandomization \
  --fields-config-path configs/fields/best_fields.yaml \
  --weights-file fingerprint_best_fields.json \
  --verify-precompute
```

## Running unit-test datasets

The repository includes a script for running IE analysis on small unit-test datasets:

```bash
bash scripts/unit_tests.sh
```

The script builds dataset names using this pattern:

```text
UT-<test_name>_<field_name>
```

For example:

```text
dataset/UT-MI1_HT_CAP_INFO/
dataset/UT-MI1_TAG_LIST/
dataset/UT-ST2_RSSI/
dataset/UT-ST2_TIME/
```

The unit-test dataset folders are intended as lightweight fixtures for validating field extraction and metric behavior.

## Outputs

Typical output files:

```text
outputs/reports/*.txt
outputs/reports/*_parallel_summary.json
outputs/figures/**/*.pdf
plots/**/*.pdf
```

Reports usually include:

- selected field configuration,
- selected weight configuration,
- distance matrix statistics,
- cluster counts,
- V-measure scores,
- pairwise metrics,
- B-cubed metrics.

## Utility scripts

- `scripts/utilities/count_frames.py` – counts frames in JSON/PCAP files.
- `scripts/utilities/count_MACs.py` – counts unique MAC addresses in PCAP/PCAPNG files.
- `scripts/utilities/count_not_PR.sh` – counts frames other than Probe Requests.
- `scripts/utilities/frames_per_device.sh` – counts frames per device directory.
- `scripts/utilities/randomizer.py` – generates replacement MAC addresses in PCAP files.
- `scripts/utilities/rename_pcaps.py` – batch-renames PCAP files.
- `scripts/utilities/PR_fields.py` – extracts Probe Request field lists from JSON/PCAP data.

## Known limitations

1. Some batch scripts expect local datasets such as `cagliari` or `awid3`, which may not be included in the repository archive.
2. Some utility scripts contain hardcoded dataset paths and may require adjustment for a different local dataset layout.
4. The full derandomization path should be checked before use with `--no-precompute`, because the distance matrix function expects the predefined penalty argument in the current implementation.
5. The project currently uses `requirements.txt`; it does not define packaging metadata in `pyproject.toml`.

## Recommended developer workflow

From the project root:

```bash
python3 -m compileall .
python3 -m src.cli.ie_analysis --help
python3 -m src.cli.fingerprints --help
python3 -m src.cli.derandomize --help
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run unit-test datasets:

```bash
bash scripts/unit_tests.sh
```

Run a small dataset first and verify that reports and plots are generated under:

```text
outputs/
```
