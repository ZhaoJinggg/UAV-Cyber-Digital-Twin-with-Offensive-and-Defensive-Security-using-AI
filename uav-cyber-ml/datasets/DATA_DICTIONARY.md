# UAV Cyber-Attack Dataset — Data Dictionary
Two independent feature layers, each with raw and processed forms.
## Timeline (attack scenarios)
All scenarios fly the **same shared multi-waypoint mission plan**. Attacks pause mid-plan:
1. **pre** — normal plan (benign label)
2. **attack** — injection (attack label)
3. **post** — resume normal plan (benign label)

Pre and post are **benign** — same normal plan flight; only the attack window is labeled as attack.

## Label columns (all files)
- `scenario` — which scenario was run
- `run` — run index
- `label_phase` — `normal_plan` | `attack`
- `attack_active` / `label_binary` — 1 only during attack
- `label_class` — `benign` | `<attack_name>` (pre + post = benign; no separate post class)
- `label_multiclass` — alias of `label_class`

## Class balance (physical_processed)
  benign: 11430
  disarm_injection: 4390
  mode_change_land: 4046
  mission_injection: 3889
  command_flood_dos: 3873
  param_injection: 3848
  rc_override: 3716
  gps_spoofing: 2421

## Phase balance (physical_processed)
  attack: 26183
  normal_plan: 11430

## Physical processed columns
t_wall, t_rel, roll, pitch, yaw, rollspeed, pitchspeed, yawspeed, x, y, z, vx, vy, vz, lat, lon, alt_msl, rel_alt, hdg, airspeed, groundspeed, heading, throttle, vfr_alt, climb, batt_voltage, batt_current, batt_remaining, cpu_load, m1, m2, m3, m4, m5, m6, m7, m8, tgt_rollrate, tgt_pitchrate, tgt_yawrate, tgt_thrust, tgt_x, tgt_y, tgt_z, tgt_vx, tgt_vy, tgt_vz, armed, custom_mode, base_mode, system_status, speed, horiz_speed, vertical_speed, tilt_mag, motor_mean, motor_spread, pos_err_z, scenario, run, label_phase, attack_active, label_binary, label_class, label_multiclass

## Network processed columns
t_rel, win_s, pkt_count, byte_count, pkt_rate, byte_rate, mean_len, std_len, mean_iat, std_iat, to_uav_count, from_uav_count, unique_msgids, unique_sysids, heartbeat_count, command_long_count, param_set_count, mission_item_count, rc_override_count, manual_control_count, gps_input_count, set_mode_count, scenario, run, label_phase, attack_active, label_binary, label_class, label_multiclass
