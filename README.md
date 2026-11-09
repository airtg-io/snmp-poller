# AIrtg snmp-poller

AIrtg snmp-poller: a fast, free and open source SNMP poller for AIrtg, written in Go.

- SNMP **v1**, **v2c** and **v3** (noAuthNoPriv, authNoPriv, authPriv; MD5, SHA, SHA-224, SHA-256,
  SHA-384, SHA-512; DES, AES-128, AES-192, AES-256 in both Blumenthal and Reeder/Cisco variants),
  **contexts**, UDP and TCP, GETBULK or GETNEXT walks, per device.
- **Credentials encrypted at rest**: community strings and passwords written in clear text are
  encrypted in place in the configuration file on startup (`~~HEX~~`, AES-256-GCM, key in
  `data/key.dat`), or read from **HashiCorp Vault** and refreshed at every discovery.
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
make build                               # or: go build -o snmp-poller ./cmd/snmp-poller
./snmp-poller -check                     # validate etc/snmp-poller.yaml and etc/conf.d, and exit
./snmp-poller                            # run with etc/snmp-poller.yaml
./snmp-poller -config /path/to/file.yaml # run with another file
./snmp-poller -encrypt foobar            # encrypt a credential by hand, see below
./snmp-poller -version
```

`make` alone runs the checks (`go vet`, gofmt, tests), then builds every platform into `dist/`
(`make dist` skips the checks): `snmp-poller-linux-amd64`,
`snmp-poller-linux-arm64`, `snmp-poller-windows-amd64.exe`, `snmp-poller-windows-arm64.exe`,
`snmp-poller-darwin-amd64` (Intel Mac) and `snmp-poller-darwin-arm64` (Apple silicon). They are
static binaries with no dependency: copy one with the `etc/` directory and run it.

Stop with `Ctrl-C` or `SIGTERM`: in-flight polls get `global.shutdown_timeout` to finish.

Relative paths (`data_dir`, log file) are relative to the working directory, except
`conf_dir`, which is relative to the directory of the configuration file.

On startup, once the configuration is valid, clear-text credentials in the configuration file
are [encrypted in place](#credentials-encryption) with the key `data/key.dat`, generated on
first start. `-check` never modifies anything.

## How it works

Every device is polled every `poll_interval` by a pool of `global.threads` workers.
First polls are spread evenly over one interval to avoid bursts. If a device is still being
polled when its next slot comes, that slot is skipped and counted as `skipped`.

Each poll:

1. **Discovery**, when due: on the first poll, then every `discovery_interval`.
   1. **Credentials**: a device using [Vault](#vault) reads its secret again. If Vault fails,
      the previous credentials are kept (a device that never got any fails its poll).
   2. **Capabilities**: every capability of `conf_dir` not excluded by the device is a
      candidate. One without `detect` applies to every device. One with `detect` applies when
      every listed OID subtree exists on the agent (one GETNEXT each).
   3. The discovery scalars of those capabilities are fetched (`sysDescr`, `sysObjectID`,
      `sysUpTime`, `sysContact`, `sysName`, `sysLocation` with the shipped `system`
      capability) and their discovery columns are walked (e.g. `ifDescr`, `ifSpeed`).
   4. Table rows are selected from the label column and the `include` patterns. For
      `high_capacity` tables (the shipped `interfaces`), the probe OID is fetched for the first
      row: if the agent answers, rows faster than `above` use their 64-bit `hc_oid` columns
      (never over SNMPv1, which cannot carry 64-bit counters).
   5. The result is saved to `data/<device_id>/discovery.json`. Every poll reads it back from
      there until the next discovery (it is not kept in memory). If the file is missing or
      corrupt, the device is rediscovered.

   Every discovery wipes the device's rate/volume state, since row indexes may have changed.
   A failed discovery fails the poll and is retried on the next poll.
2. **Collection** of the metrics of the device's capabilities: scalars and labelled table
   rows are fetched with GET requests of at most `max_oids_per_request` OIDs. Tables without
   a label are walked (GETBULK by default, GETNEXT with `walk: getnext` and always on v1) and
   filtered by row index. OIDs the agent does not have are skipped.
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
outputs, Vault and devices (with their credentials), and `etc/conf.d/` holds what to poll, one
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
| `transport` | `udp` | Default transport: `udp` or `tcp`. |
| `walk` | `bulk` | Default walk method: `bulk` (GETBULK) or `getnext` (GETNEXT, one OID per request, for agents with a broken GETBULK). SNMPv1 has no GETBULK: v1 devices always use `getnext`. |
| `data_dir` | `data` | On-disk state directory. Device directories are wiped on startup; the credentials key `key.dat` is kept. |
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

### `devices`

| Key | Default | Description |
|-----|---------|-------------|
| `id` | `<address>-<port>` | Unique id (letters, digits, `.`, `_`, `-`). Used in logs and as the data directory name. Without one, `192.0.2.10` on port 161 is `192.0.2.10-161`; other characters (IPv6 colons) become `_`: `2001_db8__1-161`. `key.dat` is reserved. |
| `address` | | Hostname, IPv4 or IPv6 address. Required. Two devices may not use the same address and port (IPs compared in canonical form, host names case-insensitively, without DNS resolution), unless they poll two different SNMPv3 contexts. |
| `port` | `global.port` | Agent port. |
| `transport` | `global.transport` | `udp` or `tcp`. |
| `walk` | `global.walk` | `bulk` or `getnext`. `bulk` on an SNMPv1 device is an error. |
| `enabled` | `true` | `false` keeps the device in the file without polling it. |
| `snmp` | | SNMP version and credentials, see below. Required. |
| `exclude` | | Capabilities never applied to this device, e.g. `[entity]`. Every other capability is polled when discovery finds it. |
| `include` | | Per-table override of the capability's `include` patterns, e.g. `{ interfaces: ["^Gi"] }`. |
| `poll_interval` | `global.poll_interval` | |
| `discovery_interval` | `global.discovery_interval` | |
| `timeout`, `retries` | global | |
| `max_oids_per_request`, `max_repetitions` | global | |
| `outputs` | all outputs | Output names to send to. |
| `trace` | `false` | Log debug details for this device only, whatever the global level. |

### `devices[].snmp`

SNMPv1 and v2c use a community string. SNMPv3 uses a username, a security level, and the
authentication and privacy protocols and passwords.

| Key | Applies to | Description |
|-----|------------|-------------|
| `version` | all | `1`, `2c` or `3` (also `v1`, `v2`, `v2c`, `v3`). Required. |
| `community` | v1, v2c | Community string. Required for v1/v2c. |
| `username` | v3 | USM user name. Required for v3. |
| `security_level` | v3 | `noAuthNoPriv`, `authNoPriv` or `authPriv`. Inferred when omitted: `authPriv` if `priv_protocol` is set, `authNoPriv` if `auth_protocol` is set, else `noAuthNoPriv`. |
| `auth_protocol` | v3 | `MD5`, `SHA` (SHA-1), `SHA224`, `SHA256`, `SHA384`, `SHA512`. Case and dashes are ignored (`sha-256` works). |
| `auth_password` | v3 | At least 8 characters. |
| `priv_protocol` | v3 | `DES`, `AES` (AES-128), `AES192`, `AES256` (Blumenthal key extension, used by net-snmp and most vendors), `AES192C`, `AES256C` (Reeder key extension, used by Cisco). |
| `priv_password` | v3 | At least 8 characters. Defaults to `auth_password`, like net-snmp's `createUser`. |
| `context_name` | v3 | SNMPv3 context name (e.g. a VRF or a bridge domain). |
| `context_engine_id` | v3 | Context engine ID as hex (`80001f8880...`, optional `0x`). Defaults to the agent's engine ID. |
| `vault` | all | Read the keys above from [Vault](#vault): `true` for the secret `<vault.prefix>/<device id>`, or a secret path (relative to the KV mount). |

Many devices can share one block with a YAML anchor (`snmp: &campus { ... }` on the first
device, `snmp: *campus` on the others), see [the example](#shared-credentials).

### Credentials encryption

Credentials (`community`, `auth_password`, `priv_password`, and the Vault `token`,
`secret_id` and `password`) are written in one of three ways:

- **Clear text**: on startup, once the whole configuration is valid, the value is encrypted
  and written back to the configuration file in place of the clear text. Only the values
  change: comments and layout are kept, and the file is replaced atomically, keeping its
  permissions. Encrypted values are on one line, so a credential written as a block scalar
  (`|`, `>`) is reported and left as is.
- **Encrypted**: `~~` + hex digit pairs + `~~`, for example `~~9F3A...C2~~`: AES-256-GCM
  (random nonce, authenticated) with the 32-byte key `<data_dir>/key.dat`. A value that does
  not match this pattern exactly is clear text, and gets encrypted.
- **Environment reference**: `${NAME}` is read from the environment on startup and never
  rewritten.

The key is generated on first start (mode `0600`) and kept when the data directory is
cleaned. **Back it up**: encrypted values cannot be read without it, and a missing or other
key makes the configuration invalid (`credentials are encrypted but the key data/key.dat does
not exist`, `cannot decrypt credential: it was encrypted with another key`). To change a
credential, write the new value in clear text: it is encrypted on the next start.

When the file cannot be written (read-only mount), the poller logs a warning and runs with
the credentials as they are. `-check` validates but never encrypts or creates the key.

#### Encrypting a credential by hand

To never write a credential in clear text, even briefly (read-only configuration, generated
or templated files), encrypt it yourself and paste the result. The value can be given three
ways:

```sh
$ ./snmp-poller -encrypt foobar              # as an argument
~~DE25456B...C1C867E~~
$ echo foobar | ./snmp-poller -encrypt       # piped: the first line, without its line ending
~~8F7B2C6F...7576030F8~~
$ ./snmp-poller -encrypt                     # typed twice, without echo
Value to encrypt:
Again:
~~E086AC64...CCF8406948~~
```

An argument is the quickest, but it is visible in your shell history and, while the command
runs, to other users through the process list: prefer the prompt on shared machines, and a
pipe from a variable or a secret manager in scripts
(`printf '%s\n' "$COMMUNITY" | ./snmp-poller -encrypt`). Quote a value with spaces or shell
characters (`-encrypt 'my pa$$word'`), and put flags before it: `-encrypt -key k.dat foobar`.

The key is `<global.data_dir>/key.dat` of the configuration file given by `-config` (default
`etc/snmp-poller.yaml`, so `data/key.dat`), or the file given by `-key`. It is generated when
missing, as on startup; encrypt with the key of the machine that runs the poller (or copy that
key file). Each run gives a different output for the same value (random nonce); all of them
decrypt to it.

The output goes on stdout, messages on stderr. Put it in place of the clear-text value, e.g.
`community: ~~3F0C9A51...D27B~~`.

### `vault`

[HashiCorp Vault](https://developer.hashicorp.com/vault) as an external store for device
credentials. A device opts in with `snmp: { vault: true }` (or a path). Its secret is a KV
secret whose keys are those of [`snmp`](#devicessnmp) (`version`, `community`, `username`,
`security_level`, `auth_protocol`, `auth_password`, `priv_protocol`, `priv_password`,
`context_name`, `context_engine_id`); any other key is an error. Secret keys override the same
keys of the device's `snmp` block, so non-secret settings can stay in the file.

The secret is read on every discovery (the first poll, then every `discovery_interval`, and
every poll while discovery fails), so rotated credentials are picked up without a restart.
It is kept in memory only. If Vault fails, the device keeps its previous credentials and a
warning is logged.

| Key | Default | Description |
|-----|---------|-------------|
| `address` | | Vault URL, `http://` or `https://`. Required. |
| `namespace` | | Vault Enterprise namespace. |
| `mount` | `secret` | Mount path of the KV secrets engine. |
| `kv_version` | `2` | KV engine version: `1` or `2`. |
| `prefix` | `snmp-poller` | Parent path of the default secret of each device: `<mount>/<prefix>/<device id>`. |
| `timeout` | `10s` | Timeout of one Vault request. |
| `ca_cert` | system CAs | PEM file of the CA that signed Vault's certificate. |
| `tls_skip_verify` | `false` | Do not verify Vault's certificate (tests only). |
| `auth.method` | | `token`, `approle`, `userpass` or `kubernetes`. Required. |
| `auth.mount` | method name | Mount path of the auth method. |
| `auth.token` | | `token`: the Vault token (encrypted like other credentials). |
| `auth.role_id`, `auth.secret_id` | | `approle`: role ID and secret ID (encrypted). |
| `auth.username`, `auth.password` | | `userpass`: user name and password (encrypted). |
| `auth.role` | | `kubernetes`: Vault role bound to the pod's service account. |
| `auth.jwt_file` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | `kubernetes`: service account token, read at each login. |

The poller logs in once for all devices and logs in again at 3/4 of the token's TTL, or when
Vault rejects the token. The Vault section is only checked for the credentials it needs when an
enabled device uses it.

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
  - address: 192.0.2.10        # id: 192.0.2.10-161
    snmp:
      version: 2c
      community: public        # encrypted in this file on startup
```

Run it with `./snmp-poller -config etc/minimal.yaml`: the device gets every capability of
`etc/conf.d` it supports (system group, interfaces, inventory). After the first start, the file
reads `community: ~~6A0F...E1~~` (see [Credentials encryption](#credentials-encryption)).

### Device ids

`id` is optional and defaults to `<address>-<port>`. Set one for a stable, readable name in
logs, outputs and the data directory.

```yaml
global:
  port: 1161                   # default port for every device

devices:
  - address: 192.0.2.11        # id: 192.0.2.11-1161
    snmp: { version: 2c, community: public }
  - address: 192.0.2.11        # same address, other port: id 192.0.2.11-161
    port: 161
    snmp: { version: 2c, community: public }
  - address: "2001:db8::12"    # id: 2001_db8__12-1161
    snmp: { version: 2c, community: public }
  - id: core-rtr1              # explicit id
    address: core-rtr1.example.net
    snmp: { version: 2c, community: public }
```

The same address and port twice (for example `10.0.0.1` and `::ffff:10.0.0.1`, or
`Router.example.net` and `router.example.net`) is an invalid configuration, except for
[SNMPv3 contexts](#snmpv3-contexts).

### SNMPv1

```yaml
devices:
  - id: legacy-ups
    address: 192.0.2.20
    snmp:
      version: 1
      community: ${SNMP_COMMUNITY}   # from the environment, never rewritten
    exclude: [interfaces]    # nothing useful there on this UPS
```

On v1, OIDs the agent does not have are removed from the request and retried, so one
unsupported OID does not hide the others. Walks always use GETNEXT (v1 has no GETBULK).

### TCP transport, custom port

```yaml
global:
  transport: udp               # the default, for every device

devices:
  - id: firewall
    address: fw.example.net
    port: 1161
    transport: tcp
    snmp: { version: 2c, community: public }
```

### Walk method: GETBULK or GETNEXT

Tables are walked with GETBULK (`max_repetitions` OIDs per request) by default. Agents with a
broken GETBULK implementation can be walked with GETNEXT, one OID per request.

```yaml
global:
  walk: bulk                   # the default, for every device

devices:
  - id: old-printer
    address: 192.0.2.25
    walk: getnext
    snmp: { version: 2c, community: public }
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
      auth_password: change-me-auth
```

### SNMPv3 authPriv, every protocol

All combinations of `auth_protocol` (`MD5`, `SHA`, `SHA224`, `SHA256`, `SHA384`, `SHA512`) and
`priv_protocol` (`DES`, `AES`, `AES192`, `AES256`, `AES192C`, `AES256C`) are supported.
`security_level` is inferred as `authPriv` here.

```yaml
devices:
  - id: r1
    address: 192.0.2.41
    snmp: { version: 3, username: mon, auth_protocol: MD5, auth_password: change-me-auth, priv_protocol: DES, priv_password: change-me-priv }
  - id: r2
    address: 192.0.2.42
    snmp: { version: 3, username: mon, auth_protocol: SHA, auth_password: change-me-auth, priv_protocol: AES, priv_password: change-me-priv }
  - id: r3
    address: 192.0.2.43
    snmp: { version: 3, username: mon, auth_protocol: SHA256, auth_password: change-me-auth, priv_protocol: AES256, priv_password: change-me-priv }
  - id: r4                     # priv_password defaults to auth_password
    address: 192.0.2.44
    snmp: { version: 3, username: mon, auth_protocol: SHA512, auth_password: change-me-auth, priv_protocol: AES192 }
  - id: r5                     # Cisco AES-192/256 need the Reeder key extension
    address: 192.0.2.45
    snmp: { version: 3, username: mon, auth_protocol: SHA, auth_password: "${SNMP_AUTH_PASS}", priv_protocol: AES256C, priv_password: "${SNMP_PRIV_PASS}" }
```

### Shared credentials

A YAML anchor (`&name`) on the first `snmp` block, and an alias (`*name`) on the others,
share one set of credentials. It is encrypted once, where the anchor is.

```yaml
devices:
  - id: bldg1-sw1
    address: 192.0.2.101
    snmp: &campus
      version: 3
      username: monitor
      auth_protocol: SHA256
      auth_password: change-me-auth
      priv_protocol: AES
      priv_password: change-me-priv
  - id: bldg1-sw2
    address: 192.0.2.102
    snmp: *campus
    poll_interval: 5m
    timeout: 10s
    retries: 3
  - id: bldg2-sw1
    address: 192.0.2.103
    snmp: *campus
```

### SNMPv3 contexts

One agent can be polled once per context, e.g. per VRF or per bridge instance: each context
is a separate device, with its own id and discovery. This is the only case where two devices
may share an address and port. `context_engine_id` is only needed by agents that proxy other
engines.

```yaml
devices:
  - id: sw1-vlan10
    address: 192.0.2.50
    snmp: &v3
      version: 3
      username: mon
      auth_protocol: SHA256
      auth_password: change-me-auth
      priv_protocol: AES
      context_name: vlan-10
  - id: sw1-vlan20
    address: 192.0.2.50
    snmp: { version: 3, username: mon, auth_protocol: SHA256, auth_password: change-me-auth, priv_protocol: AES, context_name: vlan-20 }
  - id: proxied-engine
    address: 192.0.2.51
    snmp: { version: 3, username: mon, auth_protocol: SHA256, auth_password: change-me-auth, priv_protocol: AES, context_name: remote, context_engine_id: "0x80001f888056dc3e5f5b6d2c61" }
```

### Credentials encryption

Before the first start:

```yaml
devices:
  - id: core-1
    address: 192.0.2.60
    snmp:
      version: 3
      username: poller
      auth_protocol: SHA256
      auth_password: my-auth-pass    # encrypted on startup
      priv_protocol: AES
      priv_password: ${PRIV_PASS}    # from the environment
```

After it (the key is in `data/key.dat`):

```text
devices:
  - id: core-1
    address: 192.0.2.60
    snmp:
      version: 3
      username: poller
      auth_protocol: SHA256
      auth_password: ~~5C1E09A7...4B3F~~    # encrypted on startup
      priv_protocol: AES
      priv_password: ${PRIV_PASS}    # from the environment
```

with these log lines:

```text
level=INFO msg="credentials key generated: back it up, encrypted credentials cannot be read without it" key=data/key.dat
level=INFO msg="credentials encrypted in the configuration file" config=etc/snmp-poller.yaml count=1 key=data/key.dat
```

### Vault: AppRole, default secret paths

Each device reads `secret/snmp-poller/<device id>` (KV v2), for example:

```sh
vault kv put secret/snmp-poller/core-1 version=3 username=poller \
  auth_protocol=SHA256 auth_password=my-auth-pass priv_protocol=AES priv_password=my-priv-pass
vault kv put secret/snmp-poller/edge-1 version=2c community=my-community
```

```yaml
vault:
  address: https://vault.example.net:8200
  ca_cert: /etc/snmp-poller/vault-ca.pem
  auth:
    method: approle
    role_id: 7c1f0b1e-5d2a-4f43-9d1c-1f4a7e3b9c20
    secret_id: 3b1c...           # encrypted on startup

devices:
  - id: core-1
    address: 192.0.2.80
    snmp: { vault: true }        # secret/snmp-poller/core-1
  - id: edge-1
    address: 192.0.2.81
    snmp: { vault: true }        # secret/snmp-poller/edge-1
```

### Vault: explicit paths, token, KV v1, namespace

A path shared by many devices, a per-device path, and settings in the file with only the
password in Vault (secret keys override the `snmp` block).

```yaml
vault:
  address: https://vault.example.net:8200
  namespace: network            # Vault Enterprise
  mount: kv
  kv_version: 1
  auth:
    method: token
    token: ${VAULT_TOKEN}

devices:
  - id: branch-1
    address: 192.0.2.84
    snmp: &branches { vault: branches/v2c }   # kv/branches/v2c
  - id: branch-2
    address: 192.0.2.85
    snmp: *branches
  - id: dc-core
    address: 192.0.2.86
    snmp:                       # kv/dc/core holds auth_password and priv_password
      version: 3
      username: poller
      auth_protocol: SHA512
      priv_protocol: AES256
      vault: dc/core
```

### Vault: userpass and Kubernetes

```yaml
vault:
  address: http://vault.vault.svc:8200
  prefix: network/snmp          # secrets: secret/network/snmp/<device id>
  auth:
    method: kubernetes          # the pod's service account
    role: snmp-poller
    # jwt_file: /var/run/secrets/kubernetes.io/serviceaccount/token

devices:
  - address: 192.0.2.88          # secret/network/snmp/192.0.2.88-161
    snmp: { vault: true }
```

```yaml
vault:
  address: https://vault.example.net:8200
  auth:
    method: userpass
    mount: ldap-users           # auth mount, if not "userpass"
    username: snmp-poller
    password: change-me         # encrypted on startup

devices:
  - id: core-2
    address: 192.0.2.89
    snmp: { vault: true }
```

### Capabilities per device: exclude and row filter

Every capability found by discovery is polled. `exclude` removes some for one device, and
`include` replaces the row filter of a table for one device. The shipped `interfaces` table
is labelled by `ifDescr`, so the patterns match interface descriptions.

```yaml
devices:
  - id: core-rtr1              # everything it supports, every interface
    address: 192.0.2.70
    snmp: &v2c { version: 2c, community: public }
  - id: access-sw1             # uplinks and port-channels only
    address: 192.0.2.71
    snmp: *v2c
    include:
      interfaces: ["^(TenGigabitEthernet|HundredGigE)", "^Port-channel"]
  - id: pdu1                   # no inventory, no interfaces: system group only
    address: 192.0.2.72
    snmp: *v2c
    exclude: [entity, interfaces]
```

### Discovery interval

Discovery runs on the first poll and every `discovery_interval`. Its results (capabilities,
discovery scalars and columns, selected rows) are saved in `data/<device_id>/discovery.json`.
Vault credentials are read again at each discovery.

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
- **Credentials are never logged**: community strings, passwords and Vault tokens are
  redacted in every log line, error and data file. Vault errors carry Vault's own error
  messages only.
- **Credentials**: on startup, `info` lines report a newly generated key and how many
  credentials were encrypted in the configuration file, and a `warn` line why they could not
  be (read-only file, block scalar). A device whose Vault refresh fails logs a `warn` and keeps
  its previous credentials.

## Data directory

```text
data/
  key.dat            # credentials key (32 bytes, mode 0600): back it up, never deleted
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

Device directories are wiped on startup (files such as `key.dat` are kept), and a device's
directory is wiped on each of its rediscoveries. Files are replaced atomically. The discovery and state of a device are only
loaded in memory while that device is being polled, so memory does not grow with the number
of devices, rows or polled OIDs.

## Development

```sh
make              # vet, gofmt check and tests, then cross-build every platform into dist/
make dist         # cross-build every platform, without the checks
make build        # this machine only: ./snmp-poller
make check        # go vet, gofmt check, go test
make package      # dist, then release archives and SHA256SUMS in dist/
make clean        # remove dist/ and ./snmp-poller
make help         # list targets
make VERSION=1.2.3          # override the version of the VERSION file
go test -race ./...         # with the race detector (needs a C compiler)
```

Integration tests run an in-process SNMP agent (`internal/testagent`) and exercise every SNMP
version, every v3 auth/priv combination, contexts, GETBULK and GETNEXT walks, capability
detection, the shipped capabilities (with and without ifXTable), tables, rates, Vault
credentials and the scheduler. The Vault client is tested against a fake Vault HTTP server.

| Path | Purpose |
|------|---------|
| `cmd/snmp-poller` | Entry point. |
| `internal/config` | Schema, defaults, validation, capabilities, credentials encryption (`Seal`). |
| `internal/logging` | Console and rotating file logging, per-device trace. |
| `internal/snmp` | SNMP client (gosnmp) and value conversion. |
| `internal/state` | On-disk previous values and rate/volume math. |
| `internal/vault` | HashiCorp Vault client (KV v1/v2; token, AppRole, userpass, Kubernetes auth). |
| `internal/output` | Output interface, registry and the `null` output. |
| `internal/poller` | Scheduler, workers, discovery, collection, stats. |
| `internal/testconf` | Test helper: a configuration with its capabilities in a temporary directory. |
| `etc/snmp-poller.yaml` | Default configuration. |
| `etc/conf.d/` | Shipped capabilities (`system`, `interfaces`, `entity`). |

### Versions and releases

The version is in the `VERSION` file (`MAJOR.MINOR` or `MAJOR.MINOR.PATCH`, currently `0.1`).
`snmp-poller -version` prints it with the git commit it was built from:
`AIrtg snmp-poller 0.1 (commit 10d59ad)`.

GitHub Actions (`.github/workflows/go.yml`) runs on every push to `main` and every pull
request: `make check`, then `make package`, with the archives kept as a build artifact. On a
push to `main`, if no tag `v<VERSION>` exists yet, it also creates that tag on the pushed commit
and a GitHub release named `AIrtg snmp-poller v<VERSION>`, with release notes generated from the
commits and pull requests since the previous release, and these files:

| File | Content |
|------|---------|
| `snmp-poller-<version>-linux-amd64.tar.gz`, `-linux-arm64.tar.gz` | Linux |
| `snmp-poller-<version>-darwin-amd64.tar.gz`, `-darwin-arm64.tar.gz` | macOS (Intel, Apple silicon) |
| `snmp-poller-<version>-windows-amd64.zip`, `-windows-arm64.zip` | Windows |
| `SHA256SUMS` | Checksums of the archives (`sha256sum -c SHA256SUMS`) |

Each archive holds a `snmp-poller-<version>-<os>-<arch>/` directory with the binary, `etc/`
(the configuration and `conf.d`), `README.md` and `LICENSE`, taken from the commit.

To release: change `VERSION` (e.g. `0.2`) and push to `main`. Pushing without changing
`VERSION` only builds and tests. A failing check releases nothing; once fixed, the next push
releases that version. An invalid `VERSION` fails the build.

New output types implement `output.Output` and call `output.Register` from an `init` function.
