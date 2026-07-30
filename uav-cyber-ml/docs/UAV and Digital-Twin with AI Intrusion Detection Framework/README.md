# UAV–Digital Twin–AI IDS Technical Manual

**Actual location (this folder):**

```
docs/UAV and Digital-Twin with AI Intrusion Detection Framework/
```

There is **no** `docs/technical_manual/` directory unless you create that rename or symlink when packaging for GitHub.

## Build PDF

```bash
cd "docs/UAV and Digital-Twin with AI Intrusion Detection Framework"
tectonic main.tex
open main.pdf   # macOS
```

Alternative (full TeX Live with latexmk):

```bash
latexmk -pdf -interaction=nonstopmode main.tex
```

If you have renamed/symlinked this folder to `docs/technical_manual/`, `cd` there instead.

## Structure

| Path | Content |
|------|---------|
| `main.tex` | Master file (compile this) |
| `preamble.tex` | Packages, macros, page style |
| `references.bib` | BibTeX source (for editors / future biber) |
| `chapters/references.tex` | Printed reference list used by `main.tex` |
| `chapters/ch01_…`–`ch30_…` | One file per chapter |
| `chapters/phase*_summary.tex` | Phase summaries |
| `chapters/conclusion.tex` / `future_work.tex` | Closing chapters |
| `figures/` | Screenshots and diagrams |
| `main.pdf` | Compiled handbook |

## Content mapping

- **Phase 1** — Ubuntu UAV workstation (PX4, Gazebo, optional ROS 2/DDS)
- **Phase 2** — Operational Digital Twin (`uav-cyber-ml` dashboard, recorders, scenarios)
- **Phase 3** — TinyMAV CNN + LightGBM IDS, proactive/hybrid/reactive defence

References cover real packages used in the lab (PX4, MAVLink, pymavlink, Gazebo, FastAPI, PyTorch, LightGBM, three.js, tcpdump, etc.).
