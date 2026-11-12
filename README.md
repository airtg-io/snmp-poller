# AIrtg snmp-poller

AIrtg snmp-poller: a fast, free and open source SNMP poller for AIrtg, written in Go.

- SNMP **v1**, **v2c** and **v3** (noAuthNoPriv, authNoPriv, authPriv; MD5, SHA, SHA-224, SHA-256,
  SHA-384, SHA-512; DES, AES-128, AES-192, AES-256 in both Blumenthal and Reeder/Cisco variants),
  **contexts**, UDP and TCP, GETBULK or GETNEXT walks, per device.
- **Credentials encrypted at rest**: community strings and passwords written in clear text are
  encrypted in place in the configuration files on startup (`~~HEX~~`, AES-256-GCM, key in
  `data/key.dat`), or read from **HashiCorp Vault** and refreshed at every discovery.
- **Split configuration**: process settings in `etc/snmp-poller.yaml`, devices and the rest in
  any number of files of `etc/conf.d/`, read automatically. No device is configured by default.
- **Hot reload**: edited files are validated and applied without restart (or on `SIGHUP`);
  devices keep their discovery cycle, an invalid change is logged and ignored.
- **Capabilities**: what to poll lives in `etc/capabilities.d/`, one file per capability (system
  group, interfaces, host resources, inventory, Cisco and Juniper CPUs and memory, ...). Discovery finds which capabilities each device has, and every one
  found is polled unless the device excludes it or a preferred capability replaces it.
- **Discovery** on the first poll and then every hour (configurable) for slow-changing data:
  sysDescr, sysName, sysLocation, model, interface names, ... cached **on disk**.
- **Interfaces** use 64-bit ifXTable counters when the agent has them and the interface is faster
  than 100 Mbit/s, and ifTable counters otherwise.
- **Raw values, rates and volumes.** Previous values are kept **on disk**, not in memory.
- **Row-based table polling** with inclusive regex filters on a discovered label (e.g. `ifDescr`).
- **Sinks**: **Prometheus remote write** (Prometheus, Mimir, VictoriaMetrics, Thanos, ...) and
  **InfluxDB 3**, any number of each, ready for Grafana. Each sink chooses the keys it sends
  and the tags attached to them from the discovery cache (sysName, ifName, ifAlias, ...).
  The **AIrtg analyzer** sink publishes everything, discovery included, over NATS JetStream in
  the open [AIrtg schema](https://github.com/airtg-io/schema).
  Sinks send in parallel and never delay polling; an unreachable destination's data waits in a
  **disk buffer** (1GB by default) and is sent in order once it is back. No sink, no data sent.
- **Bounded worker pool** (250 threads by default) with overrun protection.
- **Useful logs**: one stats line per minute, failures logged once per device, per-device tracing,
  console + auto-rotated file. **Credentials are never logged.**

Licensed under the GNU GPL v3 (see [LICENSE](LICENSE)).

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Configuration reference](#configuration-reference)
- [Capabilities](#capabilities)
- [Sinks](#sinks)
- [Examples](#examples)
- [Logs](#logs)
- [Data directory](#data-directory)
- [Development](#development)

## Quick start

Requires Go 1.27 or later.

```sh
make build                               # or: go build -o snmp-poller ./cmd/snmp-poller
cp etc/conf.d/devices.yaml.example etc/conf.d/devices.yaml   # then edit: your devices
cp etc/conf.d/sinks.yaml.example etc/conf.d/sinks.yaml       # then edit: where data goes
./snmp-poller -check                     # validate the configuration and the capabilities, and exit
./snmp-poller                            # run with etc/snmp-poller.yaml and etc/conf.d/*.yaml
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
Configuration changes apply without restart: see [Reloading](#reloading-the-configuration).

The shipped configuration polls nothing and sends nothing: add devices and [sinks](#sinks) in
files of `etc/conf.d` (see [Configuration files](#configuration-files)). Without devices, the
poller runs idle; without sinks, it polls but sends the data nowhere. It logs a warning for
each.

Relative paths (`data_dir`, log file) are relative to the working directory, except
`include_dir` and `capabilities_dir`, which are relative to the directory of the main
configuration file.

On startup, once the configuration is valid, clear-text credentials in the configuration files
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
   2. **Capabilities**: every capability of `capabilities_dir` not excluded by the device is a
      candidate. One without `detect` applies to every device. One with `detect` applies when
      every listed OID subtree exists on the agent (one GETNEXT each).
   3. The discovery scalars of those capabilities are fetched (`sysDescr`, `sysObjectID`,
      `sysUpTime`, `sysContact`, `sysName`, `sysLocation` with the shipped `system`
      capability) and their discovery columns are walked (e.g. `ifDescr`, `ifSpeed`). In the
      same GET, scalars with candidate `oids` pick the first one the agent has (the shipped
      `uptime` prefers `hrSystemUptime` to `sysUpTime`).
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

   Then [formulas](#formulas) compute their values from the values of this poll (e.g. storage
   bytes from allocation units). Every value is sent with its [unit](#units), the one the
   device reports it in.

   Rates and volumes need the previous value, which is read from and written to
   `data/<device_id>/state.json`. The first poll after startup or discovery has no previous
   value, so it emits only `raw`. Counter32 wraps are handled. A Counter64 that goes
   backwards is treated as a reset (no sample). Gauges and integers may give negative deltas.
   Rate/volume on non-numeric values (strings) are ignored.

   **Agent restarts.** Every poll also reads the agent's `sysUpTime`, kept in `state.json`.
   When it goes back, the agent restarted: the rates and volumes of that poll are not computed
   (the previous values predate the restart, and a counter that restarted from 0 would look
   like a Counter32 wrap), and neither are those of the next poll, because some agents report
   wrong counters on their first read after starting (net-snmp reports 0 for
   `ifInUcastPkts`, which made the next rate a huge spike). Without a previous uptime (first
   poll, or after a discovery), an agent up for less than one poll interval counts as just
   started. An `info` line `agent restarted` says so, and rates come back two polls later.
4. **Sinks**: the batch (device id, address, discovery scalars and columns, samples) is handed
   to every [sink](#sinks) of the device. Each sink picks its keys and tags, encodes the batch
   and returns at once: sending happens in the background, sink by sink.

## Configuration reference

The configuration is YAML, in three places:

| Path | Holds |
|------|-------|
| `etc/snmp-poller.yaml` | The main file: `global`, and anything else below. Shipped with the defaults, no device. |
| `etc/conf.d/*.yaml` | More configuration files, read automatically: devices (with their credentials), sinks, `vault`, `logging`. See [Configuration files](#configuration-files). |
| `etc/capabilities.d/*.yaml` | What to poll, one [capability](#capabilities) per file. |

Unknown keys are rejected, so typos are caught by `-check`. Durations use Go syntax: `500ms`,
`30s`, `5m`, `1h`.

### Configuration files

Every `*.yaml` and `*.yml` file of `global.include_dir` (`etc/conf.d` by default) is read after
the main file, in name order, and has the same format as the main file. Other files (such as
the shipped `devices.yaml.example` and `sinks.yaml.example`), hidden files and subdirectories
are ignored.

- `devices` and `sinks` of every file are combined (main file first, then the files in name
  order). Device ids, device addresses and sink ids are unique across all files.
- `logging` and `vault` may each be defined in one file only, any of them.
- `global` is only allowed in the main file.
- Clear-text credentials are [encrypted](#credentials-encryption) in the file they are written in.
- Errors name the file: `etc/conf.d/core.yaml: devices[2]: address is required`.

For example, one file per site, and Vault in its own file:

```yaml
# conf.d/site-paris.yaml
devices:
  - id: paris-core-1
    address: 192.0.2.20
    snmp: { version: 2c, community: paris-ro }   # encrypted in this file on startup
  - id: paris-ups
    address: 192.0.2.21
    snmp: { version: 1, community: "${SNMP_COMMUNITY}" }
```

```yaml
# conf.d/vault.yaml
vault:
  address: https://vault.example.net:8200
  auth: { method: token, token: "${VAULT_TOKEN}" }
devices:
  - id: paris-edge-1
    address: 192.0.2.22
    snmp: { vault: true }
```

Only files ending in `.yaml` or `.yml` are read: rename a file to `.yaml.off` to disable it. A
missing `etc/conf.d` is fine; an `include_dir` set explicitly must exist. Local files of
`etc/conf.d` are ignored by git: only the examples are part of the repository.

### Reloading the configuration

With `global.hot_reload: true` (the default), the poller checks every 2 seconds whether a file
of the configuration changed: the main file, a file of `include_dir` or of `capabilities_dir`
(added, edited or removed). A change is read once it has been stable for one check, so a file
being saved is not read half way. With `hot_reload: false`, changes wait for a `SIGHUP`
(`kill -HUP <pid>`), which reloads in any case (not available on Windows).

The new configuration is validated first, completely, as on startup. If anything fails
(syntax, validation, an output or the Vault client that cannot be built, an unwritable log
file), an `error` line says why and **the previous configuration stays in force**; the same
broken files are not reported again until they change. Otherwise it is applied at once,
and new clear-text credentials are encrypted:

```text
level=INFO msg="configuration reloaded" reason="file change" files=3 devices=12 added=1 removed=1 changed=2 rediscovered=1
level=ERROR msg="configuration reload failed, the previous configuration stays in force" reason="file change" err="etc/conf.d/core.yaml: devices[2]: address is required"
```

| Change | Effect |
|--------|--------|
| Device added | Polled from now on, first polls spread over one poll interval; discovered on its first poll. |
| Device removed | No longer polled (a poll in progress ends normally); its data directory is deleted. |
| Address, port, transport, SNMP version, credentials, context, Vault path, capabilities (excluded, edited, include patterns) of a device | The device is discovered again on its next poll. |
| Anything else on a device (intervals, timeouts, retries, walk, sinks, trace, ...) | Applied on its next poll. Its discovery cycle is kept: `discovery_interval` counts from its last discovery. A shorter `poll_interval` applies at once, a longer one after the next poll. |
| Unchanged devices | Nothing: same poll phase, same discovery cycle, rate/volume state kept. |
| `sinks` | New or changed sinks start at once; a replaced sink stops once the polls using it are done, hands its disk buffer to its successor and gets its `timeout` to send what it holds in memory. Unchanged sinks keep running untouched. |
| `vault` | A new client logs in on its next use; an unchanged section keeps its token. |
| `logging` | Applied at once (level, console, file). |
| `global.threads`, `stats_interval`, `shutdown_timeout`, `hot_reload`, defaults inherited by devices | Applied at once. |
| `global.data_dir` | Refused (error, previous configuration kept): restart to change it. |

A device being polled during a reload gets its new configuration when that poll ends.

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
| `data_dir` | `data` | On-disk state directory. Device directories are wiped on startup; the credentials key `key.dat` and the sinks' disk buffers (`sinks/`) are kept. See [Data directory](#data-directory). |
| `include_dir` | `conf.d` | [Configuration files](#configuration-files) read after the main file. Relative to the directory of the main file (`etc/conf.d` by default). Main file only. |
| `capabilities_dir` | `capabilities.d` | [Capabilities](#capabilities) directory. Relative to the directory of the main file (`etc/capabilities.d` by default). Formerly `conf_dir`, which is now rejected with a message saying so. |
| `stats_interval` | `1m` | Interval of the stats log line. |
| `shutdown_timeout` | `30s` | Grace period for in-flight polls on shutdown. |
| `hot_reload` | `true` | Reload the configuration when its files change. `false`: only on `SIGHUP`. See [Reloading](#reloading-the-configuration). |

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

### `sinks`

Where polled data goes. See [Sinks](#sinks) for what is sent and how. Without any sink,
polled data is sent nowhere.

```yaml
# conf.d/sinks.yaml
sinks:
  - id: prometheus
    type: prometheus
    url: http://prometheus:9090/api/v1/write
  - id: influxdb
    type: influxdb
    url: http://influxdb:8181
    database: snmp
    token: apiv3_xxxxxxxx               # encrypted in this file on startup
  - id: analyzer                        # the AIrtg analyzer: nothing else to set
    type: airtg
```

An `airtg` sink takes no other key than `id` and `type`: see [AIrtg analyzer](#airtg-analyzer).
The keys below are for the other types.

| Key | Default | Description |
|-----|---------|-------------|
| `id` | | Unique id (letters, digits, `.`, `_`, `-`), referenced by devices, used in logs and as the disk buffer directory name. Required. |
| `type` | | `prometheus` ([remote write](#prometheus)), `influxdb` ([InfluxDB 3](#influxdb-3)) or `airtg` ([AIrtg analyzer](#airtg-analyzer)). Required. |
| `url` | | `prometheus`: the remote write endpoint, e.g. `http://prometheus:9090/api/v1/write`. `influxdb`: the server, e.g. `http://influxdb:8181` (`/api/v2/write` is appended). Required. |
| `database` | | `influxdb` only: the database (bucket). Required. |
| `token` | | `influxdb`: sent as `Authorization: Token <token>`. `prometheus`: sent as `Authorization: Bearer <token>`. [Encrypted](#credentials-encryption) on startup like device credentials. |
| `username`, `password` | | HTTP basic authentication, instead of `token`. The password is encrypted on startup. |
| `headers` | | More HTTP headers, e.g. `{ X-Scope-OrgID: tenant-1 }` for Mimir. Not `Authorization`: use `token` or `username`/`password`, which are encrypted. |
| `ca_cert`, `client_cert`, `client_key`, `tls_skip_verify` | | TLS: CA file (PEM) to verify the server, client certificate and key (mutual TLS), or no verification (tests only). |
| `timeout` | `10s` | Per request. Also how long a stopping sink gets to send what it holds in memory. |
| `prefix` | `snmp_` (prometheus), none (influxdb) | Start of every metric name (prometheus) or measurement name (influxdb). |
| `keys` | all | `include` and `exclude` lists of regular expressions on the [keys](#keys-and-tags): a key is sent when it matches an `include` pattern (or there is none) and no `exclude` pattern. |
| `tags` | `[device, index, labels]` | Tags (labels) attached to every value, see [Keys and tags](#keys-and-tags). |
| `batch_size` | `5000` | Maximum values per request. An InfluxDB line (the values of one row) is never split: a line of more values is a request of its own. |
| `flush_interval` | `1s` | The longest a value waits for its request to fill up. |
| `disk_buffer` | `1GB` | Size limit of the [disk buffer](#delivery-and-disk-buffer) `<data_dir>/sinks/<id>/`, used while the destination is unreachable. `0` or `null`: no disk buffer. Units: `B`, `KB`, `MB`, `GB`, `TB` (powers of 1000), `KiB`, `MiB`, `GiB`, `TiB` (powers of 1024). |

Devices send to every sink by default, to the sinks listed in their `sinks`, or to none with
`sinks: []`.

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
| `sinks` | all sinks | Ids of the [sinks](#sinks) to send to; `[]` for none. |
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

- **Clear text**: on startup and on every reload, once the whole configuration is valid, the value is encrypted
  and written back to its configuration file in place of the clear text. Only the values
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
`*.yml`) file of `capabilities_dir` is one capability, named after the file. Other files are
ignored. Shipped in `etc/capabilities.d`:

| Capability | Detect | Collects |
|------------|--------|----------|
| `system` | every device | Discovery: `sysDescr`, `sysObjectID`, `sysUpTime`, `sysContact`, `sysName`, `sysLocation` (SNMPv2-MIB system group, `1.3.6.1.2.1.1`). Polled every cycle, in seconds: `uptime`, the system uptime (HOST-RESOURCES-MIB `hrSystemUptime` when the agent has it, else `sysUpTime`), and `sysUpTime`, the agent uptime. |
| `interfaces` | every device | IF-MIB counters, status and speed of every interface, with 64-bit ifXTable counters on interfaces faster than 100 Mbit/s when available (v2c and v3). |
| `entity` | `entPhysicalModelName` | Discovery: ENTITY-MIB name, model and serial number of every physical entity. |
| `host-resources` | HOST-RESOURCES-MIB (`1.3.6.1.2.1.25`) | Number of processes, memory size in kilobytes, size and use of every storage (RAM, swap, file systems) in allocation units as reported plus size, used and free bytes and used and free percentages, load of every processor. See [below](#the-host-resources-capability). |
| `cisco-cpu` | `cpmCPUTotal5minRev` | CISCO-PROCESS-MIB busy percentage of every CPU over 5 seconds, 1 minute and 5 minutes, named after its ENTITY-MIB entry. See [below](#the-cisco-cpu-capability). |
| `cisco-enhanced-mempool` | `cempMemPoolUsed` | CISCO-ENHANCED-MEMPOOL-MIB used, free and largest free bytes and used percentage of every memory pool of every card, 64-bit when available. See [below](#the-cisco-memory-capabilities). |
| `cisco-memory-pool` | `ciscoMemoryPoolUsed`, unless `cisco-enhanced-mempool` applies | CISCO-MEMORY-POOL-MIB used, free and largest free bytes and used percentage of every memory pool, for older Cisco devices. See [below](#the-cisco-memory-capabilities). |
| `juniper-cpu` | `jnxOperatingCPU` | JUNIPER-MIB busy percentage of every Routing Engine and FPC, current and over 1, 5 and 15 minutes. See [below](#the-juniper-capabilities). |
| `juniper-memory` | `jnxOperatingMemory` | JUNIPER-MIB memory size and used memory in megabytes, used percentage, and heap used percentage, of every Routing Engine and FPC. See [below](#the-juniper-capabilities). |

Every device gets every capability discovery finds, except those listed in its `exclude` and
those replaced by a capability that applies to it (`replaced_by`).
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
| `replaced_by` | Optional list of capabilities preferred to this one: when one of them applies to the device (detected, not excluded by the device, not itself replaced), this one does not. For a fallback on agents without the preferred MIB, e.g. `replaced_by: [cisco-enhanced-mempool]`. The names must be capabilities of `capabilities_dir`, and no capability may be replaced by itself, even indirectly. |
| `discovery.scalars` | Map of name to scalar OID, fetched on discovery (e.g. `sysName: 1.3.6.1.2.1.1.5.0`). Cached on disk and attached to every batch. |
| `discovery.columns` | Map of name to table column OID, walked on discovery (e.g. `ifDescr: 1.3.6.1.2.1.2.2.1.2`). Used as table labels. A column of another table can be read through a column holding its index: `{ oid, index }` gives, at each row of the `index` discovery column (of the same capability, itself a plain OID), the value of `oid` at the index that row holds (e.g. `cpuName: { oid: 1.3.6.1.2.1.47.1.1.1.1.7, index: cpmCPUTotalPhysicalIndex }`, the entPhysicalName each CPU points to). Rows whose index is not found in `oid` have no value. `{ oid, index_part: n }` gives, at each row of `oid`, the n-th sub-identifier (from 1) of the row's index, for tables indexed by another table's index (e.g. the `entPhysicalIndex` that starts the index of `cempMemPoolTable`); it can be the `index` of another column. |
| `scalars` | Metrics polled every cycle, see below. |
| `tables` | Tables polled every cycle, see below. |

### Capability `scalars`

| Key | Description |
|-----|-------------|
| `name` | Metric name. |
| `oid` | Full OID, including the instance (`.0` for scalars). Leading dot optional. |
| `oids` | Instead of `oid`: candidate OIDs, in order of preference. Discovery picks the first one the agent has, and only that one is polled until the next discovery (none: the scalar is not polled). |
| `formula` | Instead of `oid`: computes the value from scalars of the same capability defined above it. See [Formulas](#formulas). |
| `unit` | The unit the device reports the value in, sent with every sample: a word of the [unit vocabulary](#units) (e.g. `octet`, `kilobyte`, `percent`), `none` for a string. Required when the value is emitted. `/s` is appended for `rate`. |
| `modes` | List of `raw`, `rate`, `volume`. Default `[raw]`. Not allowed with `formula`, always `raw`. |
| `emit` | `false` makes the scalar an input of formulas only: polled, not sent to outputs. Default `true`. |

### Capability `tables`

| Key | Description |
|-----|-------------|
| `name` | Table name. |
| `label` | Optional discovery column naming each row (e.g. `ifDescr`). With a label, rows are selected at discovery and fetched with GET. Without one, columns are walked on every poll. |
| `include` | Optional list of regular expressions ([RE2 syntax](https://github.com/google/re2/wiki/Syntax)). A row is polled if **any** pattern matches its label (or its index when there is no label). No patterns: every row. Use anchors (`^...$`) for exact matches. Devices can override it with their own `include`. |
| `labels` | Optional extra discovery columns attached to each sample (e.g. `[ifName, ifAlias]`). |
| `high_capacity` | Optional, needs a `label`: `{ probe, speed, above }`. At discovery, `probe` (a column OID) is fetched for the first row. If the agent has it, rows whose `speed` discovery column is strictly greater than `above` (default `100000000`) use the `hc_oid` of their columns; without `speed`, every row does. Never used over SNMPv1, which cannot carry 64-bit counters. |
| `columns` | List of `{ name, oid, hc_oid, formula, unit, modes, emit }`. `oid` is the column OID, without row index. `hc_oid` is the column used on high-capacity rows instead. A column with only `hc_oid` is polled on high-capacity rows only. A column with a `formula` is computed, per row, from the columns of the same table defined above it (see [Formulas](#formulas)). `unit`, `modes` and `emit` are as for scalars. A table without `label` needs at least one column with an `oid`. |

The shipped `interfaces` capability uses `high_capacity` to pick, per interface, between the
32-bit ifTable counters and the 64-bit ifXTable counters (probing `ifHCInOctets` rather than
`ifName`, since some agents implement ifXTable names without its counters). A 32-bit octet
counter wraps every
34 s at 1 Gbit/s and every 344 s at 100 Mbit/s, so faster interfaces need 64-bit counters. Metric names do not change, the
sample type (`Counter32` or `Counter64`) tells them apart:

```yaml
# capabilities.d/interfaces.yaml (excerpt)
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
      - { name: ifInOctets, oid: 1.3.6.1.2.1.2.2.1.10, hc_oid: 1.3.6.1.2.1.31.1.1.1.6, modes: [rate, volume], unit: octet }
      - { name: ifHighSpeed, hc_oid: 1.3.6.1.2.1.31.1.1.1.15, unit: megabit/s }   # high-capacity rows only
```

### Units

Every emitted value has a unit, sent with each sample: the unit **the device reports it
in**. Values are collected as close to their source as possible and never normalized across
products: a Cisco memory pool reported in bytes is in `byte`, a Juniper memory size reported in
megabytes stays in `megabyte`. Whoever reads the data converts if it needs to.

- Units are lowercase singular words of the AIrtg unit vocabulary, shared by every AIrtg
  collector so that the same unit is always written the same way (`percent`, never `%`): see
  the [AIrtg schema](https://github.com/airtg-io/schema#rules-every-producer-and-consumer-follows).
  The most used: `octet`, `packet`, `segment`, `datagram`, `bit`, `byte`, `kilobyte`,
  `megabyte`, `allocation unit`, `percent`, `second`, `process`, `volt`, `celsius`, `watt`, and
  `enum` for a number that names a state or a thing (`ifOperStatus`: 1 up, 2 down, ...; a
  process id). A unit outside the vocabulary is an error.
- The unit names what the MIB counts: `ifInOctets` is in `octet`.
- `/s` is appended for `rate` (`octet/s`). A value that is a rate itself is written with `/s`
  (`ifSpeed` in `bit/s`), and cannot also have the `rate` mode.
- A [formula](#formulas) gives the unit of its inputs, or the one their combination gives
  (`hrStorageSize` allocation units times `hrStorageAllocationUnits` bytes is in `byte`). A
  formula that would only scale a value (kilobytes to bytes) is not written: the value is sent
  as the device reports it.
- SNMP time ticks (hundredths of a second) are the exception: they are converted to `second`
  by a formula, the unit every tool uses for durations.
- A value with no unit, a string, is written `unit: none`.

### Formulas

A scalar or a column with a `formula` is not polled: it is computed on every poll from other
values, so the configuration shows every operation applied to the data. Typical uses are
derived values (bytes from allocation units, free space, percentages) and time ticks in
seconds. A formula never only scales a value to another unit (see [Units](#units)).

- Operators: `+`, `-`, `*`, `/`, unary `-`, parentheses, with the usual precedence. Numbers
  are decimal (`1024`, `0.5`).
- Names: a scalar formula reads scalars of its capability, a column formula reads columns of
  the same row of its table, in both cases only those defined **above** it (other formulas
  included). It reads their raw value, whatever their `modes`.
- Arithmetic is exact (rational numbers): `hrStorageSize * hrStorageAllocationUnits` is exact
  even for petabytes. The result is a float when the formula has a division or a decimal
  number, otherwise an integer (a float if it does not fit in 64 bits), so a metric never
  changes type. Samples have the type `Formula` and mode `raw`.
- When a value it reads is missing (not returned by the agent, or not a number), or a divisor
  is zero (a storage of size 0), the formula gives no sample on that poll (a `debug` line
  says why).
- `emit: false` on its inputs keeps them out of the outputs. Prefer emitting them: the source
  values are what the device really reports. The shipped capabilities hide only time ticks,
  sent in seconds instead.

### The `host-resources` capability

Detected on agents that implement HOST-RESOURCES-MIB (RFC 2790), mostly servers (net-snmp,
Windows SNMP service) and some appliances. Values are sent as the agent reports them: memory
in kilobytes, storage in allocation units of `hrStorageAllocationUnits` bytes. Per storage
row, formulas also give the size, used and free space in bytes and as percentages:

| Metric | Table | Unit | From |
|--------|-------|------|------|
| `hrSystemProcesses` | | process | `hrSystemProcesses` |
| `hrMemorySize` | | kilobyte | `hrMemorySize`: the memory of the host |
| `hrStorageAllocationUnits` | `storage` | byte | Size of one allocation unit |
| `hrStorageSize` | `storage` | allocation unit | `hrStorageSize` |
| `hrStorageUsed` | `storage` | allocation unit | `hrStorageUsed` |
| `storageSize` | `storage` | byte | `hrStorageSize * hrStorageAllocationUnits` |
| `storageUsed` | `storage` | byte | `hrStorageUsed * hrStorageAllocationUnits` |
| `storageFree` | `storage` | byte | `storageSize - storageUsed` |
| `storageUsedPercent` | `storage` | percent | `storageUsed * 100 / storageSize` |
| `storageFreePercent` | `storage` | percent | `storageFree * 100 / storageSize` |
| `hrProcessorLoad` | `processors` | percent | `hrProcessorLoad`: share of the last minute the processor was busy |

Storage rows are labelled by `hrStorageDescr` (`Physical memory`, `Swap space`, `/var`, ...),
which a device's `include` can filter (e.g. `include: { storage: ["^/"] }` for file systems
only), and carry `hrStorageType` (e.g. `.1.3.6.1.2.1.25.2.1.4`, hrStorageFixedDisk).
Processor rows carry `hrDeviceDescr`. The system uptime is the `uptime` metric of the
`system` capability, which prefers `hrSystemUptime` to `sysUpTime`: on a host, `sysUpTime` is
the uptime of the SNMP agent, which can restart without the system.

```yaml
# capabilities.d/host-resources.yaml (excerpt)
discovery:
  columns:
    hrStorageDescr: 1.3.6.1.2.1.25.2.3.1.3
scalars:
  - { name: hrMemorySize, oid: 1.3.6.1.2.1.25.2.2.0, unit: kilobyte }
tables:
  - name: storage
    label: hrStorageDescr
    columns:
      - { name: hrStorageAllocationUnits, oid: 1.3.6.1.2.1.25.2.3.1.4, unit: byte }
      - { name: hrStorageSize, oid: 1.3.6.1.2.1.25.2.3.1.5, unit: allocation unit }
      - { name: hrStorageUsed, oid: 1.3.6.1.2.1.25.2.3.1.6, unit: allocation unit }
      - { name: storageSize, formula: "hrStorageSize * hrStorageAllocationUnits", unit: byte }
      - { name: storageUsed, formula: "hrStorageUsed * hrStorageAllocationUnits", unit: byte }
      - { name: storageFree, formula: "storageSize - storageUsed", unit: byte }
      - { name: storageUsedPercent, formula: "storageUsed * 100 / storageSize", unit: percent }
      - { name: storageFreePercent, formula: "storageFree * 100 / storageSize", unit: percent }
```

### The `cisco-cpu` capability

CPU utilization of Cisco devices, as recommended by Cisco in
[Collect CPU Utilization on Cisco IOS Devices with SNMP](https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/15215-collect-cpu-util-snmp.html):
CISCO-PROCESS-MIB `cpmCPUTotalTable`, one row per CPU (route processor, line card, module),
indexed by `cpmCPUTotalIndex`. Detected on devices that have `cpmCPUTotal5minRev` (IOS
12.2(3.5) and later, and the other Cisco platforms that implement the table). The deprecated
`cpmCPUTotal5sec`, `cpmCPUTotal1min` and `cpmCPUTotal5min` are not polled.

| Metric | Table | Unit | From |
|--------|-------|------|------|
| `cpmCPUTotal5secRev` | `cpu` | percent | Share of the last 5 seconds the CPU was busy |
| `cpmCPUTotal1minRev` | `cpu` | percent | Same, over the last minute |
| `cpmCPUTotal5minRev` | `cpu` | percent | Same, over the last 5 minutes: the value Cisco suggests monitoring |

Each row carries `cpmCPUTotalPhysicalIndex`, the ENTITY-MIB `entPhysicalIndex` of the CPU,
and `cpuName`, the `entPhysicalName` of that entity (e.g. `RSP at Slot 2`, `Line Card 4`),
read at discovery through the index (see `discovery.columns`). A CPU without entity
(`cpmCPUTotalPhysicalIndex` 0), or a device without ENTITY-MIB, has no `cpuName`. Cisco gives
90% of `cpmCPUTotal5minRev` as a starting alert threshold, to adjust to the platform's
baseline, and warns that polling every second or so can load the CPU of some devices.

```yaml
# capabilities.d/cisco-cpu.yaml (excerpt)
detect:
  - 1.3.6.1.4.1.9.9.109.1.1.1.1.8      # cpmCPUTotal5minRev
discovery:
  columns:
    cpmCPUTotalPhysicalIndex: 1.3.6.1.4.1.9.9.109.1.1.1.1.2
    cpuName: { oid: 1.3.6.1.2.1.47.1.1.1.1.7, index: cpmCPUTotalPhysicalIndex }
tables:
  - name: cpu
    labels: [cpuName, cpmCPUTotalPhysicalIndex]
    columns:
      - { name: cpmCPUTotal5minRev, oid: 1.3.6.1.4.1.9.9.109.1.1.1.1.8, unit: percent }
```

### The Cisco memory capabilities

Cisco devices report memory pools ("Processor", "I/O", ...) in two MIBs: the current
CISCO-ENHANCED-MEMPOOL-MIB (64-bit values, pools of every card of a chassis) and the older
CISCO-MEMORY-POOL-MIB (32-bit values only, wrong for pools of 4 GiB or more). Many devices
have both, which would report the same pools twice, so `cisco-memory-pool` has
`replaced_by: [cisco-enhanced-mempool]`: discovery checks both, and picks the enhanced MIB when
the device has it, CISCO-MEMORY-POOL-MIB otherwise. A device that excludes
`cisco-enhanced-mempool` (e.g. a buggy agent) gets `cisco-memory-pool` instead.

| Metric | Table | Unit | From |
|--------|-------|------|------|
| `cempMemPoolUsed` | `enhanced_mempool` | byte | Bytes in use: `cempMemPoolHCUsed` (64-bit) when the agent has it, else `cempMemPoolUsed` |
| `cempMemPoolFree` | `enhanced_mempool` | byte | Free bytes: `cempMemPoolHCFree` or `cempMemPoolFree` |
| `cempMemPoolLargestFree` | `enhanced_mempool` | byte | Largest contiguous free block: `cempMemPoolHCLargestFree` or `cempMemPoolLargestFree` |
| `cempMemPoolUsedPercent` | `enhanced_mempool` | percent | `cempMemPoolUsed * 100 / (cempMemPoolUsed + cempMemPoolFree)` |
| `ciscoMemoryPoolUsed` | `memory_pool` | byte | Bytes in use |
| `ciscoMemoryPoolFree` | `memory_pool` | byte | Free bytes |
| `ciscoMemoryPoolLargestFree` | `memory_pool` | byte | Largest contiguous free block |
| `ciscoMemoryPoolUsedPercent` | `memory_pool` | percent | `ciscoMemoryPoolUsed * 100 / (ciscoMemoryPoolUsed + ciscoMemoryPoolFree)` |

`enhanced_mempool` rows are indexed by `<entPhysicalIndex>.<cempMemPoolIndex>`, labelled by
`cempMemPoolName`, and carry `mempoolPhysicalIndex` (the `entPhysicalIndex`) and
`mempoolEntityName` (its ENTITY-MIB `entPhysicalName`, e.g. `RP0`, when the device has
ENTITY-MIB). The 64-bit columns are chosen at discovery, for every pool, when the agent
answers `cempMemPoolHCUsed` for the first one (never over SNMPv1). `memory_pool` rows are
indexed by `ciscoMemoryPoolType` (1 processor, 2 I/O, ...) and labelled by
`ciscoMemoryPoolName`. A low largest free block next to a high free amount means fragmented
memory.

```yaml
# capabilities.d/cisco-memory-pool.yaml (excerpt)
detect:
  - 1.3.6.1.4.1.9.9.48.1.1.1.5         # ciscoMemoryPoolUsed
replaced_by: [cisco-enhanced-mempool]
discovery:
  columns:
    ciscoMemoryPoolName: 1.3.6.1.4.1.9.9.48.1.1.1.2
tables:
  - name: memory_pool
    label: ciscoMemoryPoolName
    columns:
      - { name: ciscoMemoryPoolUsed, oid: 1.3.6.1.4.1.9.9.48.1.1.1.5, unit: byte }
```

```yaml
# capabilities.d/cisco-enhanced-mempool.yaml (excerpt)
detect:
  - 1.3.6.1.4.1.9.9.221.1.1.1.1.7      # cempMemPoolUsed
discovery:
  columns:
    cempMemPoolName: 1.3.6.1.4.1.9.9.221.1.1.1.1.3
    mempoolPhysicalIndex: { oid: 1.3.6.1.4.1.9.9.221.1.1.1.1.3, index_part: 1 }
    mempoolEntityName: { oid: 1.3.6.1.2.1.47.1.1.1.1.7, index: mempoolPhysicalIndex }
tables:
  - name: enhanced_mempool
    label: cempMemPoolName
    labels: [mempoolEntityName, mempoolPhysicalIndex]
    high_capacity:
      probe: 1.3.6.1.4.1.9.9.221.1.1.1.1.18           # cempMemPoolHCUsed: no speed, every pool
    columns:
      - { name: cempMemPoolUsed, oid: 1.3.6.1.4.1.9.9.221.1.1.1.1.7, hc_oid: 1.3.6.1.4.1.9.9.221.1.1.1.1.18, unit: byte }
```

### The Juniper capabilities

CPU and memory of Junos devices (MX, EX, QFX, PTX, SRX, ACX, vMX, vSRX, ...), from
JUNIPER-MIB `jnxOperatingTable`, the table behind `show chassis routing-engine` and
`show chassis fpc`. `juniper-cpu` is detected on devices that have `jnxOperatingCPU`,
`juniper-memory` on devices that have `jnxOperatingMemory`.

| Metric | Table | Unit | From |
|--------|-------|------|------|
| `jnxOperatingCPU` | `juniper_cpu` | percent | Current share of the time the CPU is busy |
| `jnxOperating1MinAvgCPU` | `juniper_cpu` | percent | Same, averaged over the last minute |
| `jnxOperating5MinAvgCPU` | `juniper_cpu` | percent | Same, over the last 5 minutes |
| `jnxOperating15MinAvgCPU` | `juniper_cpu` | percent | Same, over the last 15 minutes |
| `jnxOperatingBuffer` | `juniper_memory` | percent | Share of the memory in use (the CLI's "Memory utilization") |
| `jnxOperatingHeap` | `juniper_memory` | percent | Share of the heap in use (FPCs; 0 on Routing Engines) |
| `jnxOperatingMemory` | `juniper_memory` | megabyte | Installed memory, as the agent reports it |
| `jnxMemoryUsed` | `juniper_memory` | megabyte | `jnxOperatingMemory * jnxOperatingBuffer / 100`, to 1% of the size: the agent reports a whole percentage |

`jnxOperatingTable` has one row per component of the chassis (Routing Engines, FPCs, PICs,
fans, power supplies, ...), indexed by `<jnxOperatingContentsIndex>.<L1>.<L2>.<L3>` (e.g.
`9.1.0.0` for Routing Engine 0), and reports 0 for what a component does not have. Both
tables are labelled by `jnxOperatingDescr` and poll only the rows it names `Routing Engine ...`
or `FPC...` (`FPC: MPC7E 3D 40XGE @ 0/*/*`, one FPC per member of a Virtual Chassis, ...),
selected at discovery. A device can select other rows with its own
[`include`](#capabilities-per-device-exclude-and-row-filter), e.g.
`include: { juniper_cpu: ["^Routing Engine", "^FPC", "^SPC"] }`. The 1, 5 and 15 minute
averages are recent JUNIPER-MIB objects: an older Junos agent does not return them (debug
logs count and list them), and `jnxOperatingCPU` is still polled.

```yaml
# capabilities.d/juniper-memory.yaml (excerpt)
detect:
  - 1.3.6.1.4.1.2636.3.1.13.1.15       # jnxOperatingMemory
discovery:
  columns:
    jnxOperatingDescr: 1.3.6.1.4.1.2636.3.1.13.1.5
tables:
  - name: juniper_memory
    label: jnxOperatingDescr
    include: ["^Routing Engine", "^FPC"]
    columns:
      - { name: jnxOperatingMemory, oid: 1.3.6.1.4.1.2636.3.1.13.1.15, unit: megabyte }
      - { name: jnxOperatingBuffer, oid: 1.3.6.1.4.1.2636.3.1.13.1.11, unit: percent }
      - { name: jnxMemoryUsed, formula: "jnxOperatingMemory * jnxOperatingBuffer / 100", unit: megabyte }
```

### Capability examples

Each example is one file of `capabilities_dir` (the test suite validates each of them).

Raw, rate and volume:

```yaml
# capabilities.d/tcp.yaml
description: TCP statistics (MIB-II)
detect: [1.3.6.1.2.1.6]
scalars:
  # Segments: volume since the previous poll and per-second rate.
  - { name: tcpInSegs, oid: 1.3.6.1.2.1.6.10.0, modes: [rate, volume], unit: segment }
  # Gauge: current established connections.
  - { name: tcpCurrEstab, oid: 1.3.6.1.2.1.6.9.0, unit: connection }
```

A table without label: columns are walked on every poll and `include` matches the row index
(the OID suffix after the column). This suits tables whose rows change often. Formulas work
on walked rows too:

```yaml
# capabilities.d/ucd-load.yaml
description: UCD-SNMP-MIB load averages (net-snmp) and UDP listeners
detect: [1.3.6.1.4.1.2021.10]
tables:
  - name: load
    columns:
      # laLoadInt is the load average times 100 (1, 5 and 15 minutes): the
      # average number of processes running or waiting.
      - { name: laLoadInt, oid: 1.3.6.1.4.1.2021.10.1.5, emit: false }
      - { name: loadAverage, formula: "laLoadInt / 100", unit: process }
  - name: udpListeners
    include: ['^1\.4\.0\.0\.0\.0\.']   # IPv4 0.0.0.0 listeners only
    columns:
      - { name: udpEndpointProcess, oid: 1.3.6.1.2.1.7.7.1.8, unit: enum }   # a process id
```

A labelled table filtered at discovery, with extra discovery scalars:

```yaml
# capabilities.d/ups.yaml
description: UPS-MIB battery and inputs
detect: [1.3.6.1.2.1.33.1.1]
discovery:
  scalars:
    upsIdentModel: 1.3.6.1.2.1.33.1.1.2.0
  columns:
    upsInputLineIndex: 1.3.6.1.2.1.33.1.3.3.1.1
scalars:
  - { name: upsBatteryStatus, oid: 1.3.6.1.2.1.33.1.2.1.0, unit: enum }
  - { name: upsEstimatedChargeRemaining, oid: 1.3.6.1.2.1.33.1.2.4.0, unit: percent }
tables:
  - name: ups_input
    label: upsInputLineIndex
    include: ["^[12]$"]                  # first two input lines only
    columns:
      - { name: upsInputVoltage, oid: 1.3.6.1.2.1.33.1.3.3.1.3, unit: volt }
```

## Sinks

A sink sends the values of every poll of its devices to a time series database, or to the
AIrtg analyzer. Three types exist:

- [`prometheus`](#prometheus): the Prometheus remote write protocol (1.0), accepted by
  Prometheus, Grafana Mimir, VictoriaMetrics, Thanos Receive, Cortex, Grafana Cloud, ...
- [`influxdb`](#influxdb-3): InfluxDB line protocol to InfluxDB 3 Core, Enterprise and Cloud
  (the `/api/v2/write` endpoint, also served by InfluxDB 2).
- [`airtg`](#airtg-analyzer): the AIrtg analyzer, over NATS JetStream.

Grafana reads the first two out of the box. [Keys and tags](#keys-and-tags) apply to them only:
the analyzer receives every value with all its labels.

### Keys and tags

Every value has a **key**: the metric name (a scalar or a table column of a capability), with
`_rate` or `_volume` appended for those [modes](#capability-scalars): `uptime`, `ifOperStatus`,
`ifInOctets_rate`, `ifInOctets_volume`, `storageUsedPercent`. `keys.include` and
`keys.exclude` select which keys a sink sends:

```yaml
sinks:
  - id: traffic-only
    type: prometheus
    url: http://prometheus:9090/api/v1/write
    keys:
      include: ['^if(In|Out)Octets_rate$', '^ifOperStatus$']
  - id: no-volumes
    type: influxdb
    url: http://influxdb:8181
    database: snmp
    keys:
      exclude: ['_volume$']
```

**Tags** identify what a value is about. Their values come from the device and from its
discovery cache (`data/<device_id>/discovery.json`), so they cost no extra SNMP request.
`tags` is a list of sources; an entry `{ name: source }` renames one:

| Source | Value |
|--------|-------|
| `device` | The device id. |
| `address` | The device address. |
| `index` | The table row index (`1`, `10101`, ...). Table values only. |
| `table`, `capability` | The table name, the capability name. |
| `labels` | The table's `label` and `labels` columns (e.g. `ifDescr`, `ifName`, `ifAlias`), each a tag named after its column. Cannot be renamed. Table values only. |
| a discovery scalar | `sysName`, `sysLocation`, `sysDescr`, `sysContact`, `sysObjectID`, ... (any `discovery.scalars` of a capability), on every value of the device. |
| a discovery column | `ifSpeed`, `ifType`, `entPhysicalModelName`, ... (any `discovery.columns` of a capability), the row's value, on values of the tables of that capability. |

```yaml
sinks:
  - id: influxdb
    type: influxdb
    url: http://influxdb:8181
    database: snmp
    tags: [device, { host: sysName }, sysLocation, labels, index, { speed: ifSpeed }]
```

Empty values are left out. Unknown sources are configuration errors. Keep `index` or a label
that is unique per row (such as `ifDescr`): without one, the rows of a table become the same
series.

### Prometheus

Each value is a sample of the series `<prefix><key>` (`snmp_ifInOctets_rate`), with the tags as
labels and the time the value was received (ms). Strings (e.g. `sysDescr` polled as a
scalar) cannot be stored by Prometheus and are not sent. Names are made valid Prometheus names
(invalid characters become `_`); a name emitted by two tables is a configuration error (exclude
one with `keys`).

Prometheus accepts remote write when started with `--web.enable-remote-write-receiver`:

```sh
prometheus --config.file=prometheus.yml --web.enable-remote-write-receiver
```

Prometheus rejects samples older than its newest data for a series (out of order), unless
`out_of_order_time_window` allows them. The poller never sends a series out of order: the disk
buffer is sent first, in order. But after an outage longer than about an hour, Prometheus also
rejects samples older than its head block: allow them with

```yaml
# prometheus.yml
storage:
  tsdb:
    out_of_order_time_window: 1d   # longer than the outages to recover from
```

VictoriaMetrics and Mimir accept old samples by default.

In Grafana, add a Prometheus data source pointing to Prometheus, then query:

```promql
snmp_ifInOctets_rate{device="core-1"} * 8                    # bit/s per interface, legend: {{ifDescr}}
snmp_storageUsedPercent{hrStorageType=~".*25\\.2\\.1\\.4"}  # fixed disks (hrStorageFixedDisk)
max by (device) (snmp_hrProcessorLoad)                        # busiest processor per host
```

### InfluxDB 3

Values are written as InfluxDB line protocol, gzip compressed, with millisecond timestamps:

- the **measurement** is the table name (`interfaces`, `storage`, `processors`), or for
  scalars the capability name (`system`, `host-resources`), after the `prefix`;
- the **tags** are the sink's tags;
- the **fields** are the keys: all the values of one row (or of one capability's scalars) of a
  poll make one line, at the time the first of them was received.

```text
interfaces,device=core-1,ifAlias=uplink,ifDescr=TenGigE0/1,ifName=Te0/1,index=1 ifInOctets_rate=1.2e+08,ifInOctets_volume=7.2e+09,ifOperStatus=1i,ifSpeed=4294967295i 1794132000123
system,device=core-1 uptime=864000i,sysUpTime=864000i 1794132000045
```

Integers are always integer fields (`i`), whatever their SNMP type, so a field never changes
type between devices; rates and volumes are floats; strings are string fields. A tag with the
same name as a field of the same measurement (e.g. a tag `ifSpeed` on `interfaces`, which has an
`ifSpeed` field) is a configuration error: rename it (`{ speed: ifSpeed }`). InfluxDB 3 creates
the database on the first write.

```sh
influxdb3 serve --node-id node0 --object-store file --data-dir ~/.influxdb3
influxdb3 create token --admin            # the token of the sink
```

In Grafana, add an **InfluxDB** data source with the query language **SQL**, the URL of the
server, the database and the token, then query:

```sql
SELECT time, "ifDescr", "ifInOctets_rate" * 8 AS bps
FROM interfaces
WHERE device = 'core-1' AND $__timeFilter(time)
ORDER BY time
```

### AIrtg analyzer

The `airtg` sink publishes to the AIrtg analyzer, in the
[AIrtg schema](https://github.com/airtg-io/schema) (Protobuf, Apache-2.0): what it sends is
documented there, and anyone can read it.

```yaml
# conf.d/analyzer.yaml
sinks:
  - id: analyzer
    type: airtg
```

- **Nothing to configure**: the sink takes only its `id`. It publishes to the analyzer's NATS
  server at `nats://127.0.0.1:4222`, a fixed address, so the poller and the analyzer must share
  a network: the same host, or the same container. Separate containers do not reach each other
  on `127.0.0.1` unless one joins the other's network namespace (Docker Compose:
  `network_mode: "service:<other>"`). Bundling the analyzer in the same container as the
  poller is planned.
  The other parameters are the defaults of every sink: 1GB disk buffer, `10s` timeout,
  requests of up to 5000 values sent within `1s`. A configuration has at most one `airtg` sink;
  devices select it with `sinks` like any other.
- **What is sent**: after each discovery of a device, an `Inventory` on
  `airtg.v1.inventory.<device>` (its capabilities, discovery scalars such as sysName and
  sysDescr, and discovery columns such as ifName and ifAlias, by row); after each poll, its
  samples in one or more `MetricBatch` on `airtg.v1.metrics.<device>` (each value with its
  capability, table, row index and labels, mode, SNMP type, unit and time, and the device's
  poll interval). A poll is split into several messages to keep each one under 512KB. Strings
  that are not valid UTF-8 (device octet strings may hold anything) are sent with U+FFFD in
  place of the invalid bytes.
- **Delivery**: each message is published with JetStream and counts as sent once the analyzer
  has stored it. Until the analyzer is running and has created its stream, data waits in the
  disk buffer, as for any unreachable destination. Each message carries a unique id, also
  sent as the `Nats-Msg-Id` header, so that the analyzer drops a message published twice.
- **Identity**: messages identify the producer as `snmp-poller` with its version and host
  name, and devices by their [id](#device-ids): give a device the same id everywhere it is
  collected from.

### Delivery and disk buffer

- **Parallel and non-blocking**: a poll hands its batch to each of its sinks and moves on. Each
  sink groups values into requests (at most `batch_size` values, sent when full or `flush_interval` after the oldest) and
  sends them from its own goroutine, one request at a time, in order. A slow or unreachable
  destination never delays polling or the other sinks.
- **Unreachable destination** (connection error, timeout, HTTP 5xx, 429, 401, 403, 404; for
  the analyzer, also no stream yet): the
  sink logs one `warn` line, keeps its data in the **disk buffer** `<data_dir>/sinks/<id>/` and
  retries (after 1s, doubling up to 30s). New data goes to the end of the buffer. Once the
  destination is back, an `info` line reports the outage duration and the buffer is sent, oldest
  first, then the sink goes back to sending from memory. Fix a wrong token or URL with a
  [reload](#reloading-the-configuration): the buffer is kept and sent with the new settings.
- **Full disk buffer**: beyond `disk_buffer`, the oldest data is dropped (logged, and counted
  in the [stats](#logs)), so the most recent data is kept.
- **Without disk buffer** (`disk_buffer: 0`): data waits in memory (up to 32MB of compressed
  requests, oldest dropped beyond) and is lost on stop.
- **Rejected data** (other HTTP 4xx, e.g. 400 invalid data; for the analyzer, a message larger
  than its server accepts or refused by its stream): that request is dropped with a `warn`
  line, so it cannot block the ones after it.
- **Restarts**: on stop, each sink gets its `timeout` to send what it holds in memory; the
  rest goes to its disk buffer, which the next run sends first. A crash loses at most the data
  of the last `flush_interval`; after one, data sent but not yet recorded as sent may be sent
  twice, which both databases ignore (same series, same time), and the analyzer drops (same
  message id) within its duplicate window.
- **Reload**: a sink whose settings change is replaced; the new one takes over the disk
  buffer. A buffer written by a sink of another type is dropped (logged), not sent.
- The disk buffer of a sink removed from the configuration stays on disk: it is sent if the
  sink comes back, or delete `<data_dir>/sinks/<id>/` by hand.

## Examples

Every example below is a complete main configuration file, used with the capabilities
shipped in `etc/capabilities.d` (the test suite validates each of them). Everything but `global`
can equally go in a file of `etc/conf.d`, as in the first one.

### Minimal: SNMPv2c

```yaml
# conf.d/devices.yaml
devices:
  - address: 192.0.2.10        # id: 192.0.2.10-161
    snmp:
      version: 2c
      community: public        # encrypted in this file on startup
```

Save it as `etc/conf.d/devices.yaml` and run `./snmp-poller`: the device gets every capability
of `etc/capabilities.d` it supports (system group, interfaces, host resources, inventory, Cisco and Juniper CPUs and memory). After the first start, the file
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
level=INFO msg="credentials encrypted in the configuration" files=etc/conf.d/devices.yaml count=1 key=data/key.dat
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

Every capability found by discovery is polled, except those replaced by a preferred one
(`replaced_by`, e.g. `cisco-memory-pool` when `cisco-enhanced-mempool` applies). `exclude` removes some for one device, and
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

### Multiple sinks

```yaml
sinks:
  - id: prometheus
    type: prometheus
    url: https://mimir.example.net/api/v1/push
    headers: { X-Scope-OrgID: network }
    username: snmp-poller
    password: change-me                 # encrypted in this file on startup
    ca_cert: /etc/ssl/certs/internal-ca.pem
  - id: influxdb
    type: influxdb
    url: http://influxdb:8181
    database: snmp
    token: "${INFLUXDB_TOKEN}"
    tags: [device, { host: sysName }, sysLocation, labels, index]
    disk_buffer: 10GB                   # long outages
  - id: lab
    type: influxdb
    url: http://lab-influxdb:8181
    database: lab
    disk_buffer: 0                      # no disk buffer: data is dropped while down

devices:
  - id: everywhere          # no sinks list: sent to every sink
    address: 192.0.2.110
    snmp: { version: 2c, community: "${SNMP_COMMUNITY}" }
  - id: lab-only
    address: 192.0.2.111
    sinks: [lab]
    snmp: { version: 2c, community: "${SNMP_COMMUNITY}" }
  - id: polled-not-sent
    address: 192.0.2.112
    sinks: []
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
    avg_duration=412ms max_duration=9.8s total_polls_ok=88231 total_polls_failed=902
  ```

  | Field | Meaning |
  |-------|---------|
  | `in_progress` | Polls running now. |
  | `queued` | Polls waiting for a free worker. Constantly high: increase `threads`. |
  | `failing_devices` | Devices whose last poll failed. |
  | `polls_ok`, `polls_failed` | Polls finished during the window. |
  | `skipped` | Poll slots skipped because the previous poll of that device was still running. |
  | `discoveries`, `discovery_failed` | Discovery runs during the window. |
  | `samples` | Values produced during the window (before each sink's `keys`). |
  | `avg_duration`, `max_duration` | Poll durations during the window. |
  | `total_*` | Since startup. |

- A **sink stats line** per sink, after the stats line:

  ```text
  level=INFO msg="sink stats" sink=influxdb state=up samples_sent=183950 requests=61
    failed_requests=0 samples_dropped=0 backlog_samples=72 backlog_bytes=0
  ```

  | Field | Meaning |
  |-------|---------|
  | `state` | `up`, or `down` while the destination is unreachable. |
  | `samples_sent`, `requests` | Values accepted by the destination, and requests sent, during the window. |
  | `failed_requests` | Requests that failed (retried, or dropped when rejected). |
  | `samples_dropped` | Values lost during the window: rejected by the destination, or dropped from a full buffer. |
  | `backlog_samples`, `backlog_bytes` | Values waiting to be sent now, and the size of the disk buffer. |

- **Sinks log on change**: a `warn` when a destination becomes unreachable (with the error), an
  `info` when it is back (with the outage duration and backlog), a `warn` at most once a minute
  while data is dropped.
- **Failures are logged on change**: the first failure of a device is a `warn` with its
  `device` id and the error, and its recovery is an `info`. Repeated failures only show up in
  the stats line, so a dead device does not flood the logs.
- **Tracing**: `trace: true` on a device (or `logging.level: debug` for all) adds debug lines
  for that device only, all tagged with `device=<id>`: capabilities not detected or replaced, discovery
  results (capabilities, selected and high-capacity rows), poll
  duration and sample count, OIDs the agent did not return, skipped polls.
- **Credentials are never logged**: community strings, passwords and Vault tokens are
  redacted in every log line, error and data file. Vault errors carry Vault's own error
  messages only.
- **Reloads**: an `info` line per applied configuration (devices added, removed, changed,
  rediscovered), an `error` line per rejected one, with the reason.
- **Credentials**: on startup and reload, `info` lines report a newly generated key and how many
  credentials were encrypted in which configuration files, and a `warn` line why they could not
  be (read-only file, block scalar). A device whose Vault refresh fails logs a `warn` and keeps
  its previous credentials.

## Data directory

```text
data/
  key.dat            # credentials key (32 bytes, mode 0600): back it up, never deleted
  <device_id>/
    discovery.json   # discovery cache: capabilities, scalars, columns, selected rows, scalar sources
    state.json       # previous value and timestamp of every rate/volume OID
  sinks/
    <sink_id>/       # disk buffer of a sink, only while it holds data
      00000000000000000001.seg   # requests not sent yet, oldest first (segments up to 64MB)
      cursor                     # read position in the first segment
```

For example, for a switch with ifXTable:

```json
{
  "time": "2026-11-08T10:00:00.123456789Z",
  "capabilities": ["entity", "interfaces", "system"],
  "scalars": { "sysName": "access-sw1", "sysLocation": "rack 1", "sysUpTime": "8640000", "...": "..." },
  "columns": { "ifDescr": { "1": "TenGigE0/1", "2": "GigE0/2" }, "ifSpeed": { "1": "4294967295", "2": "1000000000" } },
  "tables": { "interfaces": { "rows": ["1", "2"], "high_capacity": true, "high_capacity_rows": ["1", "2"] } },
  "sources": { "uptime": ".1.3.6.1.2.1.1.3.0" }
}
```

Device directories are wiped on startup (`key.dat` and `sinks/` are kept), and a device's
directory is wiped on each of its rediscoveries and when a reload removes the device. Files are replaced atomically. The discovery and state of a device are only
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
credentials, the scheduler and the sinks. The Vault client is tested against a fake Vault HTTP
server; the sinks against fake destinations, their requests decoded with independent parsers
(protobuf wire format, InfluxData's line protocol parser).

| Path | Purpose |
|------|---------|
| `cmd/snmp-poller` | Entry point. |
| `internal/config` | Schema, defaults, validation, capabilities, credentials encryption (`Seal`). |
| `internal/logging` | Console and rotating file logging, per-device trace. |
| `internal/snmp` | SNMP client (gosnmp) and value conversion. |
| `internal/state` | On-disk previous values and rate/volume math. |
| `internal/vault` | HashiCorp Vault client (KV v1/v2; token, AppRole, userpass, Kubernetes auth). |
| `internal/sink` | Sinks: Prometheus remote write and InfluxDB encoders, HTTP sender, disk buffer. |
| `internal/poller` | Scheduler, workers, discovery, collection, configuration reload, stats. |
| `internal/testconf` | Test helper: a configuration with its capabilities in a temporary directory. |
| `etc/snmp-poller.yaml` | Default main configuration (no device). |
| `etc/conf.d/` | Local configuration files (git-ignored), `devices.yaml.example` and `sinks.yaml.example`. |
| `etc/capabilities.d/` | Shipped capabilities (`system`, `interfaces`, `entity`, `host-resources`, `cisco-cpu`, `cisco-enhanced-mempool`, `cisco-memory-pool`, `juniper-cpu`, `juniper-memory`). |

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
(the main configuration, `conf.d` with its example and `capabilities.d`), `README.md` and `LICENSE`, taken from the commit.

To release: change `VERSION` (e.g. `0.2`) and push to `main`. Pushing without changing
`VERSION` only builds and tests. A failing check releases nothing; once fixed, the next push
releases that version. An invalid `VERSION` fails the build.
