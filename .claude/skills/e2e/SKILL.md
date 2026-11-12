---
name: e2e
description: Run snmp-poller end to end on the dev box against a real net-snmp agent and real backends (Prometheus, InfluxDB 3, Grafana, a NATS server for the AIrtg analyzer sink). Use it before calling a change to the poller done, or to reproduce a bug as a user would see it.
---

# End-to-end testing of snmp-poller

## The dev box

- arm64, and `/tmp` is a small tmpfs: scratch files go in the session scratchpad, downloaded
  servers under `~/.cache/snmp-poller-e2e` (already there: `bin/`, `net-snmp/root`, Prometheus,
  InfluxDB and Grafana data).
- Kill servers with `pgrep -f "[p]attern"` or by PID, never a bare pattern (it matches the
  calling shell).
- Real-backend E2E needs the user's approval: auto mode blocks it otherwise.

## Running the poller

- Copy `etc/` to a scratch dir, add `etc/conf.d/devices.yaml` there, and run the package
  (`go run ./cmd/snmp-poller` or a built binary), not `main.go` alone.
- Never commit a sealed shipped file or a local `etc/conf.d/*.yaml`.
- After a run, the device file holds the encrypted community: restore it in clear text when
  wiping `data/`.

## A real SNMP agent, without root

- net-snmp is extracted under `~/.cache/snmp-poller-e2e/net-snmp/root`. To redo it:
  `apt-get download snmpd snmp libsnmp40t64 libsnmp-base`, then `dpkg -x` each into that dir.
- Run `snmpd -C -c <conf> -I -smux` on a high port, with `LD_LIBRARY_PATH`,
  `SNMP_PERSISTENT_DIR` and `MIBS=""` set. Give snmpd its address on the command line only: an
  `agentaddress` line too makes it fail to bind.
- net-snmp supports every v3 combination (AES192/256 = Blumenthal), and contexts via
  `access ... <context> ...`.

## Real backends

- The linux-arm64 releases of Prometheus (with `--web.enable-remote-write-receiver`),
  InfluxDB 3 Core (`influxdb3 create token --admin`) and Grafana, under
  `~/.cache/snmp-poller-e2e`.
- The AIrtg analyzer sink: `go build -o ~/.cache/snmp-poller-e2e/bin/nats-server
  github.com/nats-io/nats-server/v2` (pinned in go.mod), run it with
  `-a 127.0.0.1 -p 4222 -js -sd <dir>`, plus a small consumer (scratch module requiring the
  schema and nats.go) that creates a stream on `airtg.v1.>` and decodes envelopes. Or run the
  real analyzer from `../airtg-analyzer` (see its `e2e` skill).

## Afterwards

Stop every server you started, and restore the device file if `data/` was wiped.
