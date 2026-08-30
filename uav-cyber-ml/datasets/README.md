# Datasets layout

This folder holds **per-run recordings**, **merged ML matrices**, and the
**data dictionary**. Everything is produced on the Digital Twin (DT) host
(Mac/Linux) while PX4 + Gazebo SITL runs on the Physical Twin (PT).

## Directory map

```
datasets/
├── README.md                          # this file
├── DATA_DICTIONARY.md                 # column docs + class balance
├── paper_live_metrics.json            # optional live-defence metrics dump
├── physical_processed_dataset.csv     # merged, resampled physical features
├── network_processed_dataset.csv      # merged, 1 s network windows
├── physical_raw_dataset.csv           # merged per-message physical (LARGE)
├── network_raw_dataset.csv            # merged per-packet network (LARGE)
└── runs/
    ├── benign/
    │   └── run_00/
    │       ├── metadata.json
    │       ├── physical_raw.csv
    │       ├── physical_processed.csv
    │       ├── network_raw.csv
    │       ├── network_processed.csv
    │       └── network_capture.pcap   # optional; needs sudo/tcpdump
    ├── gps_spoofing/
    ├── disarm_injection/
    └── …                              # one folder per scenario id
```

## How runs are created

1. Dashboard scenario button **or** `orchestrator.py` (see root `README.md`).
2. Each successful run writes the next free `run_NN/` under `runs/<scenario>/`.
3. Labels and attack windows are stored in `metadata.json`.
4. `python build_dataset.py` merges all runs into the top-level `*_dataset.csv`
   files and refreshes `DATA_DICTIONARY.md`.

## Labeling convention

All scenarios fly the **same shared multi-waypoint mission**. Attack runs are
split into:

| Phase | `label_phase` | `label_binary` / `attack_active` | `label_class` |
|-------|---------------|----------------------------------|---------------|
| Pre-attack plan | `normal_plan` | 0 | `benign` |
| Injection window | `attack` | 1 | `<attack_name>` |
| Post-attack resume | `normal_plan` | 0 | `benign` |
| Pure benign run | `normal_plan` | 0 | `benign` |

See `DATA_DICTIONARY.md` for every column.

## Reproducibility and data release

| Artefact | Typical size (lab) | In-repo vs archive |
|----------|--------------------|--------------------|
| `DATA_DICTIONARY.md` | KB | In-repo |
| `network_processed_dataset.csv` | ~hundreds of KB | Suitable in-repo sample |
| `physical_processed_dataset.csv` | ~tens of MB | Optional in-repo / release asset |
| `*_raw_dataset.csv` | 100 MB–GB | External archive (e.g. Zenodo / Releases) |
| `runs/**/*.pcap`, `*_raw.csv` | large per run | External archive |
| `runs/**/metadata.json` | KB | In-repo (provenance) |
| `runs/**/*_processed.csv` | ~MB | Optional small sample only |

Keep `runs/.gitkeep` so the path exists on a fresh clone; regenerate data with the
orchestrator or dashboard. A public sample may include one short benign run
(`metadata.json` + processed CSVs only) rather than the full `datasets/runs/` tree.
