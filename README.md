# AIrtg SNMP Poller

A fast, free and open source SNMP poller for AIrtg, written in Go.

- SNMP **v1**, **v2c** and **v3** (noAuthNoPriv, authNoPriv, authPriv; MD5, SHA, SHA-224, SHA-256,
  SHA-384, SHA-512; DES, AES-128, AES-192, AES-256 in both Blumenthal and Reeder/Cisco variants),
  **contexts**, UDP and TCP.
- **Capabilities**: what to poll lives in `etc/conf.d/`, one file per capability (system group,
  interfaces, inventory, ...). Discovery finds which capabilities each device has, and every one
  found is polled unless the device excludes it.
- **Discovery** on the first poll and then every hour (configurable) for slow-changing data:
  sysDescr, sysName, sysLocation, model, interface names, ... cached **on disk**.
- **Interfaces** use 64-bit ifXTable counters when the agent has them and the interface is faster
  than 100 Mbit/s, and ifTable counters otherwise.
- **Raw values, rates and volumes.** Previous values are kept **on disk**, not in memory.
- **Row-based table polling** with inclusive regex filters on a discovered label (e.g. `ifDescr`).
- **Pluggable outputs** with multiple destinations. Only `null` exists for now.
- **Bounded worker pool** (250 threads by default) with overrun protection.
- **Useful logs**: one stats line per minute, failures logged once per device, per-device tracing,
  console + auto-rotated file. **Credentials are never logged.**

Licensed under the GNU GPL v3 (see [LICENSE](LICENSE)).

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Configuration reference](#configuration-reference)
- [Capabilities](#capabilities)
- [Examples](#examples)
- [Logs](#logs)
- [Data directory](#data-directory)
- [Development](#development)

## Quick start

Requires Go 1.27 or later.

```sh
go build -o snmp-poller ./cmd/snmp-poller
./snmp-poller -check                     # validate etc/snmp-poller.yaml and etc/conf.d, and exit
./snmp-poller                            # run with etc/snmp-poller.yaml
./snmp-poller -config /path/to/file.yaml # run with another file
./snmp-poller -version
```

Stop with `Ctrl-C` or `SIGTERM`: in-flight polls get `global.shutdown_timeout` to finish.

Relative paths (`data_dir`, log file) are relative to the working directory, except
`conf_dir`, which is relative to the directory of the configuration file.

## How it works

Every device is polled every `poll_interval` by a pool of `global.threads` workers.
First polls are spread evenly over one interval to avoid bursts. If a device is still being
polled when its next slot comes, that slot is skipped and counted as `skipped`.

Each poll:

1. **Discovery**, when due: on the first poll, then every `discovery_interval`.
   1. **Capabilities**: every capability of `conf_dir` not excluded by the device is a
      candidate. One without `detect` applies to every device. One with `detect` applies when
      every listed OID subtree exists on the agent (one GETNEXT each).
   2. The discovery scalars of those capabilities are fetched (`sysDescr`, `sysObjectID`,
      `sysUpTime`, `sysContact`, `sysName`, `sysLocation` with the shipped `system`
      capability) and their discovery columns are walked (e.g. `ifDescr`, `ifSpeed`).
   3. Table rows are selected from the label column and the `include` patterns. For
      `high_capacity` tables (the shipped `interfaces`), the probe OID is fetched for the first
      row: if the agent answers, rows faster than `above` use their 64-bit `hc_oid` columns
      (never over SNMPv1, which cannot carry 64-bit counters).
   4. The result is saved to `data/<device_id>/discovery.json`. Every poll reads it back from
      there until the next discovery (it is not kept in memory). If the file is missing or
      corrupt, the device is rediscovered.

   Every discovery wipes the device's rate/volume state, since row indexes may have changed.
   A failed discovery fails the poll and is retried on the next poll.
2. **Collection** of the metrics of the device's capabilities: scalars and labelled table
   rows are fetched with GET requests of at most `max_oids_per_request` OIDs. Tables without
   a label are walked (GETBULK on v2c/v3, GETNEXT on v1) and filtered by row index. OIDs the
   agent does not have are skipped.
3. **Computation**: for every value, each configured mode is emitted:
   - `raw`: the value as returned (integer, unsigned, float or string).
   - `volume`: `v2 - v1`.
   - `rate`: `(v2 - v1) / (t2 - t1)`, per second.

   Rates and volumes need the previous value, which is read from and written to
   `data/<device_id>/state.json`. The first poll after startup or discovery has no previous
   value, so it emits only `raw`. Counter32 wraps are handled. A Counter64 that goes
   backwards is treated as a reset (no sample). Gauges and integers may give negative deltas.
   Rate/volume on non-numeric values (strings) are ignored.
4. **Output**: the batch (device id, address, capabilities, discovery scalars, samples) is
   handed to every output of the device.

## Configuration reference

The configuration is YAML: the main file (`etc/snmp-poller.yaml`) holds the process settings,
outputs, credentials and devices, and `etc/conf.d/` holds what to poll, one
[capability](#capabilities) per file. Unknown keys are rejected, so typos are caught by `-check`.
Durations use Go syntax: `500ms`, `30s`, `5m`, `1h`.

### `global`

| Key | Default | Description |
|-----|---------|-------------|
| `threads` | `250` | Worker pool size (maximum concurrent polls). |
| `poll_interval` | `60s` | Default poll interval for devices (minimum `1s`). |
| `discovery_interval` | `1h` | Default rediscovery interval for devices. |
| `timeout` | `5s` | Default timeout of one SNMP request. |
| `retries` | `1` | Default retries of one SNMP request. |
| `max_oids_per_request` | `30` | Default varbinds per GET (1-128). Requests are split automatically, and halved if the agent answers `tooBig`. |
| `max_repetitions` | `25` | Default GETBULK max-repetitions for walks (v2c/v3). |
| `port` | `161` | Default agent port. |
| `data_dir` | `data` | On-disk state directory. Wiped on startup. |
| `conf_dir` | `conf.d` | [Capabilities](#capabilities) directory. Relative to the directory of the configuration file (`etc/conf.d` by default). |
| `stats_interval` | `1m` | Interval of the stats log line. |
| `shutdown_timeout` | `30s` | Grace period for in-flight polls on shutdown. |

### `logging`

| Key | Default | Description |
|-----|---------|-------------|
| `level` | `info` | `debug`, `info`, `warn` or `error`. |
| `local_time` | `false` | Use the local time zone instead of UTC for record timestamps and rotated file names. |
| `console.enabled` | `true` | Log to stderr. |
| `file.enabled` | `true` | Log to a file. |
| `file.path` | `logs/snmp-poller.log` | Log file. Its directory is created if needed. |
| `file.max_size_mb` | `50` | Rotate when the file reaches this size. |
| `file.max_backups` | `10` | Rotated files to keep (`0` keeps all). |
| `file.max_age_days` | `30` | Delete rotated files older than this (`0` never). |
| `file.compress` | `true` | Gzip rotated files. |

Records are always plain text (logfmt), on the console and in the file. Every timestamp is
RFC 3339 with milliseconds and an explicit time zone: `2026-11-08T10:00:00.000Z` in UTC (the
default), or `2026-11-08T11:00:00.000+01:00` with `local_time: true`.

When `logs/snmp-poller.log` reaches `max_size_mb`, it is renamed with the rotation time and a
new file is started. Rotated files are then gzipped:

```text
logs/snmp-poller.log                                # current file
logs/snmp-poller-2026-11-08T10-00-00.000.log.gz     # rotated, compressed
logs/snmp-poller-2026-11-07T22-41-17.512.log.gz
```

### `outputs`

A list of destinations. With no `outputs` section, a single `null` output named `null` is used.

| Key | Description |
|-----|-------------|
| `name` | Unique name, referenced by devices. |
| `type` | Output type. Available: `null` (discards everything). |

Devices send to every output by default, or to the subset listed in their `outputs`.

### `credentials`

Named, reusable SNMP settings (`name: { ... }`), referenced by devices with `credential:`.
A device's inline `snmp:` block can be used instead, or on top of a credential to override
some of its fields. Credentials are only validated when a device uses them.

| Key | Applies to | Description |
|-----|------------|-------------|
| `version` | all | `1`, `2c` or `3` (also `v1`, `v2`, `v2c`, `v3`). Required. |
| `transport` | all | `udp` (default) or `tcp`. |
| `community` | v1, v2c | Community string. Required for v1/v2c. |
| `username` | v3 | USM user name. Required for v3. |
| `security_level` | v3 | `noAuthNoPriv`, `authNoPriv` or `authPriv`. Inferred when omitted: `authPriv` if `priv_protocol` is set, `authNoPriv` if `auth_protocol` is set, else `noAuthNoPriv`. |
| `auth_protocol` | v3 | `MD5`, `SHA` (SHA-1), `SHA224`, `SHA256`, `SHA384`, `SHA512`. Case and dashes are ignored (`sha-256` works). |
| `auth_passphrase` | v3 | At least 8 characters. |
| `priv_protocol` | v3 | `DES`, `AES` (AES-128), `AES192`, `AES256` (Blumenthal key extension, used by net-snmp and most vendors), `AES192C`, `AES256C` (Reeder key extension, used by Cisco). |
| `priv_passphrase` | v3 | At least 8 characters. |
| `context_name` | v3 | SNMPv3 context name (e.g. a VRF or a bridge domain). |
| `context_engine_id` | v3 | Context engine ID as hex (`80001f8880...`, optional `0x`). Defaults to the agent's engine ID. |

**Secrets** (`community`, `auth_passphrase`, `priv_passphrase`) can reference environment
variables with `${NAME}`, so they do not have to be stored in the file. They are never written
to logs, error messages or data files.

### `devices`

| Key | Default | Description |
|-----|---------|-------------|
| `id` | | Unique id (letters, digits, `.`, `_`, `-`). Used in logs and as the data directory name. |
| `address` | | Hostname, IPv4 or IPv6 address. |
| `port` | `global.port` | Agent port. |
| `enabled` | `true` | `false` keeps the device in the file without polling it. |
| `credential` | | Name of a `credentials` entry. |
| `snmp` | | Inline SNMP settings (same keys as `credentials`); overrides `credential` fields. |
| `exclude` | | Capabilities never applied to this device, e.g. `[entity]`. Every other capability is polled when discovery finds it. |
| `include` | | Per-table override of the capability's `include` patterns, e.g. `{ interfaces: ["^Gi"] }`. |
| `poll_interval` | `global.poll_interval` | |
| `discovery_interval` | `global.discovery_interval` | |
| `timeout`, `retries` | global | |
| `max_oids_per_request`, `max_repetitions` | global | |
| `outputs` | all outputs | Output names to send to. |
| `trace` | `false` | Log debug details for this device only, whatever the global level. |

## Capabilities

A capability is a set of OIDs to collect from devices that support it. Each `*.yaml` (or
`*.yml`) file of `conf_dir` is one capability, named after the file. Other files are ignored.
Shipped in `etc/conf.d`:

| Capability | Detect | Collects |
|------------|--------|----------|
| `system` | every device | Discovery: `sysDescr`, `sysObjectID`, `sysUpTime`, `sysContact`, `sysName`, `sysLocation` (SNMPv2-MIB system group, `1.3.6.1.2.1.1`). Polled every cycle: `sysUpTime`. |
| `interfaces` | every device | IF-MIB counters, status and speed of every interface, with 64-bit ifXTable counters on interfaces faster than 100 Mbit/s when available (v2c and v3). |
| `entity` | `entPhysicalModelName` | Discovery: ENTITY-MIB name, model and serial number of every physical entity. |

Every device gets every capability discovery finds, except those listed in its `exclude`.
Scalar and table names must be unique across all capabilities, since several of them apply
to the same device. A discovery entry may appear in several capabilities with the same OID.
Several metrics, in one or several capabilities, may read the same OID: it is fetched once per
poll, and every metric gets its samples from that one value. Previous values are stored per
OID, so a `rate` and a `volume` (or two metrics) on one OID share one delta.
A table can only use discovery columns of its own capability as labels.

### Capability file

| Key | Description |
|-----|-------------|
| `description` | Free text. |
| `detect` | Optional list of OID subtrees that must **all** exist on the agent (checked with one GETNEXT each, at discovery). Without `detect`, the capability applies to every device. |
| `discovery.scalars` | Map of name to scalar OID, fetched on discovery (e.g. `sysName: 1.3.6.1.2.1.1.5.0`). Cached on disk and attached to every batch. |
| `discovery.columns` | Map of name to table column OID, walked on discovery (e.g. `ifDescr: 1.3.6.1.2.1.2.2.1.2`). Used as table labels. |
| `scalars` | Metrics polled every cycle, see below. |
| `tables` | Tables polled every cycle, see below. |

### Capability `scalars`

| Key | Description |
|-----|-------------|
| `name` | Metric name. |
| `oid` | Full OID, including the instance (`.0` for scalars). Leading dot optional. |
| `modes` | List of `raw`, `rate`, `volume`. Default `[raw]`. |

### Capability `tables`

| Key | Description |
|-----|-------------|
| `name` | Table name. |
| `label` | Optional discovery column naming each row (e.g. `ifDescr`). With a label, rows are selected at discovery and fetched with GET. Without one, columns are walked on every poll. |
| `include` | Optional list of regular expressions ([RE2 syntax](https://github.com/google/re2/wiki/Syntax)). A row is polled if **any** pattern matches its label (or its index when there is no label). No patterns: every row. Use anchors (`^...$`) for exact matches. Devices can override it with their own `include`. |
| `labels` | Optional extra discovery columns attached to each sample (e.g. `[ifName, ifAlias]`). |
| `high_capacity` | Optional, needs a `label`: `{ probe, speed, above }`. At discovery, `probe` (a column OID) is fetched for the first row. If the agent has it, rows whose `speed` discovery column is strictly greater than `above` (default `100000000`) use the `hc_oid` of their columns. Never used over SNMPv1, which cannot carry 64-bit counters. |
| `columns` | List of `{ name, oid, hc_oid, modes }`. `oid` is the column OID, without row index. `hc_oid` is the column used on high-capacity rows instead. A column with only `hc_oid` is polled on high-capacity rows only. |

The shipped `interfaces` capability uses `high_capacity` to pick, per interface, between the
32-bit ifTable counters and the 64-bit ifXTable counters (probing `ifHCInOctets` rather than
`ifName`, since some agents implement ifXTable names without its counters). A 32-bit octet
counter wraps every
34 s at 1 Gbit/s and every 344 s at 100 Mbit/s, so faster interfaces need 64-bit counters. Metric names do not change, the
sample type (`Counter32` or `Counter64`) tells them apart:

```yaml
# conf.d/interfaces.yaml (excerpt)
discovery:
  columns:
    ifDescr: 1.3.6.1.2.1.2.2.1.2
    ifSpeed: 1.3.6.1.2.1.2.2.1.5
tables:
  - name: interfaces
    label: ifDescr
    high_capacity:
      probe: 1.3.6.1.2.1.31.1.1.1.6     # ifHCInOctets.<first interface>: 64-bit counters are there
      speed: ifSpeed
      above: 100000000                  # 100 Mbit/s
    columns:
      - { name: ifInOctets, oid: 1.3.6.1.2.1.2.2.1.10, hc_oid: 1.3.6.1.2.1.31.1.1.1.6, modes: [rate, volume] }
      - { name: ifHighSpeed, hc_oid: 1.3.6.1.2.1.31.1.1.1.15 }   # high-capacity rows only
```

### Capability examples

Each example is one file of `conf_dir` (the test suite validates each of them).

A vendor capability, polled only on devices that have the Cisco CPU MIB:

```yaml
# conf.d/cisco-cpu.yaml
description: Cisco CPU load
detect:
  - 1.3.6.1.4.1.9.9.109.1.1.1.1.8      # cpmCPUTotal5minRev
tables:
  - name: cisco_cpu
    columns:
      - { name: cpmCPUTotal5minRev, oid: 1.3.6.1.4.1.9.9.109.1.1.1.1.8 }
```

Raw, rate and volume:

```yaml
# conf.d/tcp.yaml
description: TCP statistics (MIB-II)
detect: [1.3.6.1.2.1.6]
scalars:
  # Segments: volume since the previous poll and per-second rate.
  - { name: tcpInSegs, oid: 1.3.6.1.2.1.6.10.0, modes: [rate, volume] }
  # Gauge: current established connections.
  - { name: tcpCurrEstab, oid: 1.3.6.1.2.1.6.9.0 }
```

A table without label: columns are walked on every poll and `include` matches the row index
(the OID suffix after the column). This suits tables whose rows change often.

```yaml
# conf.d/host.yaml
description: HOST-RESOURCES-MIB processors and UDP listeners
detect: [1.3.6.1.2.1.25.3.3]
tables:
  - name: cpu
    columns:
      - { name: hrProcessorLoad, oid: 1.3.6.1.2.1.25.3.3.1.2 }
  - name: udpListeners
    include: ['^1\.4\.0\.0\.0\.0\.']   # IPv4 0.0.0.0 listeners only
    columns:
      - { name: udpEndpointProcess, oid: 1.3.6.1.2.1.7.7.1.8 }
```

A labelled table filtered at discovery, with extra discovery scalars:

```yaml
# conf.d/ups.yaml
description: UPS-MIB battery and inputs
detect: [1.3.6.1.2.1.33.1.1]
discovery:
  scalars:
    upsIdentModel: 1.3.6.1.2.1.33.1.1.2.0
  columns:
    upsInputLineIndex: 1.3.6.1.2.1.33.1.3.3.1.1
scalars:
  - { name: upsBatteryStatus, oid: 1.3.6.1.2.1.33.1.2.1.0 }
  - { name: upsEstimatedChargeRemaining, oid: 1.3.6.1.2.1.33.1.2.4.0 }
tables:
  - name: ups_input
    label: upsInputLineIndex
    include: ["^[12]$"]                  # first two input lines only
    columns:
      - { name: upsInputVoltage, oid: 1.3.6.1.2.1.33.1.3.3.1.3 }
```

## Examples

Every example below is a complete main configuration file, used with the capabilities
shipped in `etc/conf.d` (the test suite validates each of them).

### Minimal: SNMPv2c

```yaml
devices:
  - id: core-sw1
    address: 192.0.2.10
    snmp:
      version: 2c
      community: ${SNMP_COMMUNITY}
```

Run it with `SNMP_COMMUNITY=... ./snmp-poller -config etc/minimal.yaml`: the device gets every
capability of `etc/conf.d` it supports (system group, interfaces, inventory).

### SNMPv1

```yaml
devices:
  - id: legacy-ups
    address: 192.0.2.20
    snmp:
      version: 1
      community: ${SNMP_COMMUNITY}
    exclude: [interfaces]    # nothing useful there on this UPS
```

On v1, OIDs the agent does not have are removed from the request and retried, so one
unsupported OID does not hide the others.

### SNMPv2c over TCP, custom port

```yaml
devices:
  - id: firewall
    address: fw.example.net
    port: 1161
    snmp:
      version: 2c
      transport: tcp
      community: ${SNMP_COMMUNITY}
```

### SNMPv3 noAuthNoPriv

```yaml
devices:
  - id: lab-switch
    address: 192.0.2.30
    snmp:
      version: 3
      username: monitor
```

### SNMPv3 authNoPriv

```yaml
devices:
  - id: access-sw
    address: 192.0.2.31
    snmp:
      version: 3
      username: monitor
      security_level: authNoPriv
      auth_protocol: SHA256
      auth_passphrase: ${SNMP_AUTH_PASS}
```

### SNMPv3 authPriv, every protocol

All combinations of `auth_protocol` (`MD5`, `SHA`, `SHA224`, `SHA256`, `SHA384`, `SHA512`) and
`priv_protocol` (`DES`, `AES`, `AES192`, `AES256`, `AES192C`, `AES256C`) are supported.
`security_level` is inferred as `authPriv` here.

```yaml
credentials:
  v3-md5-des:
    { version: 3, username: mon, auth_protocol: MD5, auth_passphrase: "${SNMP_AUTH_PASS}", priv_protocol: DES, priv_passphrase: "${SNMP_PRIV_PASS}" }
  v3-sha-aes128:
    { version: 3, username: mon, auth_protocol: SHA, auth_passphrase: "${SNMP_AUTH_PASS}", priv_protocol: AES, priv_passphrase: "${SNMP_PRIV_PASS}" }
  v3-sha256-aes256:
    { version: 3, username: mon, auth_protocol: SHA256, auth_passphrase: "${SNMP_AUTH_PASS}", priv_protocol: AES256, priv_passphrase: "${SNMP_PRIV_PASS}" }
  v3-sha512-aes192:
    { version: 3, username: mon, auth_protocol: SHA512, auth_passphrase: "${SNMP_AUTH_PASS}", priv_protocol: AES192, priv_passphrase: "${SNMP_PRIV_PASS}" }
  # Cisco devices using AES-192/256 need the Reeder key extension:
  v3-cisco-aes256:
    { version: 3, username: mon, auth_protocol: SHA, auth_passphrase: "${SNMP_AUTH_PASS}", priv_protocol: AES256C, priv_passphrase: "${SNMP_PRIV_PASS}" }

devices:
  - { id: r1, address: 192.0.2.41, credential: v3-md5-des }
  - { id: r2, address: 192.0.2.42, credential: v3-sha-aes128 }
  - { id: r3, address: 192.0.2.43, credential: v3-sha256-aes256 }
  - { id: r4, address: 192.0.2.44, credential: v3-sha512-aes192 }
  - { id: r5, address: 192.0.2.45, credential: v3-cisco-aes256 }
```

### SNMPv3 contexts

One device can be polled once per context, e.g. per VRF or per bridge instance: each context
is a separate device, with its own discovery. `context_engine_id` is only needed by agents that
proxy other engines.

```yaml
credentials:
  v3:
    version: 3
    username: mon
    auth_protocol: SHA256
    auth_passphrase: ${SNMP_AUTH_PASS}
    priv_protocol: AES
    priv_passphrase: ${SNMP_PRIV_PASS}

devices:
  - id: sw1-vlan10
    address: 192.0.2.50
    credential: v3
    snmp: { context_name: vlan-10 }
  - id: sw1-vlan20
    address: 192.0.2.50
    credential: v3
    snmp: { context_name: vlan-20 }
  - id: proxied-engine
    address: 192.0.2.51
    credential: v3
    snmp: { context_name: remote, context_engine_id: "0x80001f888056dc3e5f5b6d2c61" }
```

### Capabilities per device: exclude and row filter

Every capability found by discovery is polled. `exclude` removes some for one device, and
`include` replaces the row filter of a table for one device. The shipped `interfaces` table
is labelled by `ifDescr`, so the patterns match interface descriptions.

```yaml
credentials:
  v2c: { version: 2c, community: "${SNMP_COMMUNITY}" }

devices:
  - id: core-rtr1              # everything it supports, every interface
    address: 192.0.2.70
    credential: v2c
  - id: access-sw1             # uplinks and port-channels only
    address: 192.0.2.71
    credential: v2c
    include:
      interfaces: ["^(TenGigabitEthernet|HundredGigE)", "^Port-channel"]
  - id: pdu1                   # no inventory, no interfaces: system group only
    address: 192.0.2.72
    credential: v2c
    exclude: [entity, interfaces]
```

### Discovery interval

Discovery runs on the first poll and every `discovery_interval`. Its results (capabilities,
discovery scalars and columns, selected rows) are saved in `data/<device_id>/discovery.json`.

```yaml
global:
  discovery_interval: 6h        # default for every device

devices:
  - id: edge1
    address: 192.0.2.90
    snmp: { version: 2c, community: "${SNMP_COMMUNITY}" }
  - id: lab-device
    address: 192.0.2.91
    snmp: { version: 2c, community: "${SNMP_COMMUNITY}" }
    discovery_interval: 10m     # this one changes often
```

### Credentials and overrides

```yaml
credentials:
  campus:
    version: 3
    username: monitor
    auth_protocol: SHA256
    auth_passphrase: ${SNMP_AUTH_PASS}
    priv_protocol: AES
    priv_passphrase: ${SNMP_PRIV_PASS}

devices:
  - id: bldg1-sw1
    address: 192.0.2.101
    credential: campus
  - id: bldg1-sw2
    address: 192.0.2.102
    credential: campus
    snmp: { username: monitor-ro }    # same credential, other user
    poll_interval: 5m
    timeout: 10s
    retries: 3
```

### Multiple outputs

```yaml
outputs:
  - { name: primary, type: "null" }
  - { name: archive, type: "null" }

devices:
  - id: everywhere          # no outputs list: sent to every output
    address: 192.0.2.110
    snmp: { version: 2c, community: "${SNMP_COMMUNITY}" }
  - id: archive-only
    address: 192.0.2.111
    outputs: [archive]
    snmp: { version: 2c, community: "${SNMP_COMMUNITY}" }
```

### Logging: console only, debug level, local time

```yaml
logging:
  level: debug
  local_time: true
  console: { enabled: true }
  file: { enabled: false }

devices:
  - id: r1
    address: 192.0.2.120
    snmp: { version: 2c, community: "${SNMP_COMMUNITY}" }
```

### Logging: file rotation, and tracing one device

```yaml
logging:
  level: info
  console: { enabled: false }
  file:
    path: /var/log/snmp-poller/snmp-poller.log
    max_size_mb: 100
    max_backups: 5
    max_age_days: 14
    compress: true

devices:
  - id: troublesome
    address: 192.0.2.130
    trace: true      # debug logs for this device only
    snmp: { version: 2c, community: "${SNMP_COMMUNITY}" }
  - id: quiet
    address: 192.0.2.131
    snmp: { version: 2c, community: "${SNMP_COMMUNITY}" }
```

### Large deployment tuning

```yaml
global:
  threads: 1000                # more concurrent polls
  poll_interval: 5m
  timeout: 3s
  retries: 2
  max_oids_per_request: 50     # fewer round trips (lower it for agents answering tooBig)
  max_repetitions: 50
  data_dir: /var/lib/snmp-poller
  stats_interval: 5m

devices:
  - id: r1
    address: 192.0.2.140
    snmp: { version: 2c, community: "${SNMP_COMMUNITY}" }
  - id: decommissioned
    address: 192.0.2.141
    enabled: false             # kept for reference, not polled
    snmp: { version: 2c, community: "${SNMP_COMMUNITY}" }
```

## Logs

Logs are meant to be read: there is no line per poll at `info` level.

- Startup and shutdown lines.
- A **stats line** every `stats_interval`:

  ```text
  level=INFO msg="poller stats" window=1m0s devices=1200 in_progress=37 queued=4 failing_devices=3
    polls_ok=1180 polls_failed=17 skipped=0 discoveries=21 discovery_failed=2 samples=184022
    output_errors=0 avg_duration=412ms max_duration=9.8s total_polls_ok=88231 total_polls_failed=902
  ```

  | Field | Meaning |
  |-------|---------|
  | `in_progress` | Polls running now. |
  | `queued` | Polls waiting for a free worker. Constantly high: increase `threads`. |
  | `failing_devices` | Devices whose last poll failed. |
  | `polls_ok`, `polls_failed` | Polls finished during the window. |
  | `skipped` | Poll slots skipped because the previous poll of that device was still running. |
  | `discoveries`, `discovery_failed` | Discovery runs during the window. |
  | `samples` | Samples sent to outputs during the window. |
  | `output_errors` | Failed output writes. |
  | `avg_duration`, `max_duration` | Poll durations during the window. |
  | `total_*` | Since startup. |

- **Failures are logged on change**: the first failure of a device is a `warn` with its
  `device` id and the error, and its recovery is an `info`. Repeated failures only show up in
  the stats line, so a dead device does not flood the logs.
- **Tracing**: `trace: true` on a device (or `logging.level: debug` for all) adds debug lines
  for that device only, all tagged with `device=<id>`: capabilities not detected, discovery
  results (capabilities, selected and high-capacity rows), poll
  duration and sample count, OIDs the agent did not return, skipped polls.
- **Credentials are never logged**: community strings and passphrases are redacted in every
  log line, error and data file.

## Data directory

```text
data/
  <device_id>/
    discovery.json   # discovery cache: capabilities, scalars, columns, selected rows
    state.json       # previous value and timestamp of every rate/volume OID
```

For example, for a switch with ifXTable:

```json
{
  "time": "2026-11-08T10:00:00.123456789Z",
  "capabilities": ["entity", "interfaces", "system"],
  "scalars": { "sysName": "access-sw1", "sysLocation": "rack 1", "sysUpTime": "8640000", "...": "..." },
  "columns": { "ifDescr": { "1": "TenGigE0/1", "2": "GigE0/2" }, "ifSpeed": { "1": "4294967295", "2": "1000000000" } },
  "tables": { "interfaces": { "rows": ["1", "2"], "high_capacity": true, "high_capacity_rows": ["1", "2"] } }
}
```

The whole directory is wiped on startup, and a device's directory is wiped on each of its
rediscoveries. Files are replaced atomically. The discovery and state of a device are only
loaded in memory while that device is being polled, so memory does not grow with the number
of devices, rows or polled OIDs.

## Development

```sh
go build ./...
go vet ./...
gofmt -l .
go test -race ./...
```

Integration tests run an in-process SNMP agent (`internal/testagent`) and exercise every SNMP
version, every v3 auth/priv combination, contexts, capability detection, the shipped
capabilities (with and without ifXTable), tables, rates and the scheduler.

| Path | Purpose |
|------|---------|
| `cmd/snmp-poller` | Entry point. |
| `internal/config` | Schema, defaults, validation, capabilities, resolution of credentials. |
| `internal/logging` | Console and rotating file logging, per-device trace. |
| `internal/snmp` | SNMP client (gosnmp) and value conversion. |
| `internal/state` | On-disk previous values and rate/volume math. |
| `internal/output` | Output interface, registry and the `null` output. |
| `internal/poller` | Scheduler, workers, discovery, collection, stats. |
| `internal/testconf` | Test helper: a configuration with its capabilities in a temporary directory. |
| `etc/snmp-poller.yaml` | Default configuration. |
| `etc/conf.d/` | Shipped capabilities (`system`, `interfaces`, `entity`). |

New output types implement `output.Output` and call `output.Register` from an `init` function.
