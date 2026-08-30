# Physical Twin (PT) setup — Ubuntu UAV workstation

These are the scripts that run **on the UAV PC**, not on the Digital Twin host.
`ssh_control.py` invokes `scripts/start_sitl_baseline.sh` over SSH when you press
**Start sim** in the dashboard, so the PT will not start without them.

They are kept here so the testbed can be reproduced on a fresh machine. They are
**not** used by the DT-side Python package.

---

## 1. Prerequisites on the UAV PC

- Ubuntu with a graphical session (Gazebo Classic needs a display)
- [PX4-Autopilot](https://docs.px4.io/main/en/dev_setup/dev_env_linux_ubuntu.html)
  cloned to `~/PX4-Autopilot` and built once:
  ```bash
  git clone https://github.com/PX4/PX4-Autopilot.git --recursive ~/PX4-Autopilot
  cd ~/PX4-Autopilot && bash ./Tools/setup/ubuntu.sh
  make px4_sitl gazebo-classic          # first build takes a while
  ```
- An SSH server, reachable from the DT host:
  ```bash
  sudo apt install openssh-server
  ```

## 2. Install these scripts

```bash
mkdir -p ~/uav_cyber_testbed
cp -r pt-setup/scripts pt-setup/config ~/uav_cyber_testbed/
chmod +x ~/uav_cyber_testbed/scripts/*.sh
```

The path `~/uav_cyber_testbed` is not arbitrary — it is `config.TESTBED_DIR` on
the DT side. Change both if you move it.

## 3. Key-based SSH from the DT

`ssh_control.py` runs SSH with `BatchMode=yes`, so password login will not work.
From the **DT host**:

```bash
ssh-keygen -t ed25519            # if you have no key yet
ssh-copy-id <user>@<PT-ip>
ssh -o BatchMode=yes <user>@<PT-ip> echo ok    # must print: ok
```

## 4. Check it

From the **DT host**:

```bash
python scripts/uav_link.py --host <PT-ip> --user <user>
```

All six checks should pass. Then start the dashboard and press **Start sim**.

---

## How telemetry reaches the Digital Twin

This is the part that most often goes wrong, so it is worth understanding.

**PX4 SITL only sends MAVLink to localhost by default.** Its startup log says so:

```
INFO [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
```

Meanwhile the DT's recorder *binds* `udpin:0.0.0.0:14550` and waits to be sent
to. If nothing tells PX4 where the DT is, the DT waits forever: the dashboard
loads, SSH works, Gazebo runs — and the twin never moves.

`enable_qgc_mavlink.sh` closes that gap. After SITL is up it starts a MAVLink
instance aimed at the DT:

```
mavlink start -x -u 14541 -r 4000000 -t <DT-ip> -o 14550
```

It finds `<DT-ip>` from **`$SSH_CLIENT`** — the address of whoever SSHed in to
start SITL, which is by definition the Digital Twin. That means **DHCP works with
no configuration on either side**: whatever address the DT has today is the
address PX4 sends to.

Override the auto-detection when you need to:

| Variable | Meaning |
|----------|---------|
| `DT_IP` | Force a specific DT address instead of `$SSH_CLIENT` |
| `DT_GCS_PORT` | Port on the DT to send to (default `14550`) |

Setting `MAV_0_BROADCAST=1` is the alternative PX4 suggests, but it does not
survive a restart: `make px4_sitl` regenerates the parameter file each run, so
the setting is lost. Targeting the DT explicitly is why this approach is used.

## Files

| File | Role |
|------|------|
| `scripts/start_sitl_baseline.sh` | Stops old SITL, starts PX4 + Gazebo Classic, starts the XRCE agent, then calls `enable_qgc_mavlink.sh` |
| `scripts/enable_qgc_mavlink.sh` | Points a MAVLink instance at the Digital Twin (see above) |
| `config/lab_env.sh` | Paths and ports (`PX4_ROOT`, `TESTBED_ROOT`, port numbers) |

`config/lab_env.sh` still carries a static `QGC_HOST` as a last-resort fallback.
It is only used if `$SSH_CLIENT` is unavailable and `DT_IP` is unset.
