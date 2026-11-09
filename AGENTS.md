# AIrtg snmp-poller - agent memory

AIrtg snmp-poller: free and open source (GPLv3, see `LICENSE`) SNMP poller for AIrtg, written in Go.
This file is the project's agent memory: every feature and hard requirement lives here.
Keep it current when features are added or changed. User-facing docs live in `README.md`.

## Hard requirements (do not regress)

- **Language**: Go only. Build: `make` (default = `make check`, i.e. vet + gofmt + tests, then
  `make dist`: all platforms into `dist/`, linux, windows, darwin x amd64, arm64; static,
  CGO_ENABLED=0; a failing check builds nothing), `make dist` (without checks), `make package`
  (archives with etc/ from the git commit + SHA256SUMS), `make build` (host).
- **Version and releases**: version in `VERSION` (MAJOR.MINOR[.PATCH]), embedded with the commit
  (`-version`). CI (`.github/workflows/go.yml`) builds every push/PR; a push to main whose
  version has no tag `v<version>` yet creates the tag and a GitHub release with the archives.
  Unchanged VERSION = build only. Never create release tags by hand for unreleased versions. Plain `go build ./cmd/snmp-poller` / `go test ./...` work too.
- **Configuration**: YAML. Main file `etc/snmp-poller.yaml` (flag `-config`). `-check` validates and exits.
  Every `*.yaml`/`*.yml` of `global.include_dir` (default `conf.d`, i.e. `etc/conf.d`; hidden
  files, subdirs and other extensions ignored; missing = fine unless set explicitly) is read
  after it in name order, same schema: `devices`/`sinks` concatenated (ids, endpoints,
  sink ids unique across files), `logging`/`vault` in one file only, `global` main file
  only. Errors name their file. Config files hold process settings, outputs, `vault` and
  sinks only: **no SNMP metric definitions** (no profiles, no inline sets, no named
  credentials: reuse = YAML anchors, within one file). What to poll lives in
  `global.capabilities_dir` (default `capabilities.d`; both dirs relative to the main file).
  Old `conf_dir`, `outputs` (top level and per device) and capability files found in conf.d
  are rejected with an explanatory error.
- **Shipped config**: valid, polls and sends nothing: main file with defaults only (no devices,
  no sinks, no vault), `etc/conf.d/devices.yaml.example` and `sinks.yaml.example` (not
  loaded; validated by a test once renamed).
  Test devices live in tests only. Local `etc/conf.d/*.yaml` are git-ignored.
- **Capabilities**: one `*.yaml`/`*.yml` file per capability in capabilities_dir, named after the file.
  No `detect` = applies to every device; `detect: [oid...]` = applies when every OID subtree
  exists (one GETNEXT each, at discovery). Every capability found is polled unless the device
  lists it in `exclude` or it is `replaced_by` a capability that applies (detected, not
  excluded, not itself replaced; names checked, no cycles) - the only two ways to remove one. Devices may override a table's
  `include` with `include: {table: [...]}`. Names are unique across capabilities; labels must
  come from the same capability. Shipped: `system` (always; sysDescr, sysObjectID, sysUpTime,
  sysContact, sysName, sysLocation as discovery scalars; polled: `uptime` = hrSystemUptime if
  the agent has it, else sysUpTime (sysUpTime is the agent's uptime, not the system's), and
  sysUpTime), `interfaces` (always), `entity` (detected), `host-resources` (detected:
  hrSystemProcesses, memorySize, hrStorageTable size/used/free in bytes + used/free percent,
  hrProcessorLoad), `cisco-cpu` (detected: CISCO-PROCESS-MIB cpmCPUTotal5sec/1min/5minRev per
  CPU, per Cisco doc 15215; deprecated non-Rev objects not polled; rows named `cpuName` =
  entPhysicalName via cpmCPUTotalPhysicalIndex), `cisco-enhanced-mempool` (detected,
  per pool and entity, 64-bit HC columns via `high_capacity` probe without `speed` = all rows)
  and its fallback `cisco-memory-pool` (CISCO-MEMORY-POOL-MIB, `replaced_by` the enhanced one:
  never both). A discovery column is an OID, `{oid, index}` (read at the index held by another
  discovery column of the same capability, itself without `index`) or `{oid, index_part: n}`
  (rows of oid, value = n-th sub-id of the row index), for cross-table names.
- **Formulas, units, fallbacks**: a scalar is exactly one of `oid`, `oids` (candidates in
  preference order, the first the agent has is chosen at discovery, cached as `sources` in
  discovery.json) or `formula`; a column is `oid`/`hc_oid` or `formula`. Formulas (`+ - * /`,
  parentheses, numbers, names of values defined above: same capability for scalars, same row
  for columns) make every computation visible in the config. Exact `big.Rat` arithmetic;
  result float64 iff the formula has `/` or a decimal number, else int64 (type never flips);
  missing input or division by zero = no sample. Always raw (no modes), Sample.Type `Formula`.
  `emit: false` = input only. `unit` is passed to Sample.Unit (`/s` appended for rate). Every
  size is sent in bytes: convert device units (KiB, allocation units) with formulas.
- **Reload**: `global.hot_reload` (default true) checks the files' fingerprint every 2s
  (`Config.DiskFingerprint` vs `Fingerprint`, change applied once stable for one check);
  SIGHUP (`Poller.Reload`) reloads in any case. New config fully validated (Load, outputs,
  Vault client, logging) before anything changes; failure = error log, previous config kept,
  not retried until the files change. `data_dir` change refused (restart). Applied in the
  scheduler goroutine (`poller/reload.go`): devices matched by id; unchanged and
  settings-only changes keep their poll phase and discovery cycle; rediscovery only when
  `DeviceSpec.DiscoveryKey` changes (agent, credentials, context, Vault path, capability
  fingerprints incl. include patterns). A device being polled gets its config when the poll
  ends; replaced sinks close (in the background, Run waits) after the polls that may use them; removed devices' data dirs
  are deleted; worker pool resized. The logger (`logging.Logger.Reconfigure`) is live:
  derived loggers follow. The key is always created on startup/reload (`Seal`).
- **Shared OIDs**: an OID used by several metrics (same or different capabilities, discovery or
  polling) is fetched/walked once per cycle and emitted for each. Previous values in state.json
  are keyed by OID, so rate and volume (and every metric on that OID) share one delta.
- **Interfaces**: ifXTable 64-bit counters are used per interface when the agent answers a GET
  of ifHCInOctets.<first ifIndex> (`high_capacity.probe`) and that interface's ifSpeed is
  > 100 Mbit/s (`hc_oid` columns; 32-bit octets wrap in 34 s at 1G); otherwise ifTable (`oid`). Never on SNMPv1 (no Counter64,
  net-snmp hides them: found E2E). The probe is a counter, not ifName: some agents have ifXTable
  names without counters. Same metric names either way. Rows are labelled by ifDescr so
  ifTable-only agents work.
- **Devices**: `id` optional, default `<address>-<port>` (invalid id chars -> `_`; `key.dat`
  reserved). Same address+port twice (canonical IP, case-insensitive host, no DNS) is an
  invalid config, except for different SNMPv3 `context_name` (per-VRF polling, documented).
  `transport` udp (default)/tcp and `walk` bulk (default)/getnext per device, defaults in
  `global`; v1 always getnext, explicit `walk: bulk` on v1 is an error.
- **Credentials**: in the device's `snmp:` block (v1/v2c `community`; v3 `username`,
  `security_level`, `auth_protocol`, `auth_password`, `priv_protocol`, `priv_password`
  defaulting to auth_password). Clear-text secrets are **encrypted in place**, in the file
  they are written in, on startup once the config is valid (`Config.Seal`, not on `-check`;
  a file that fails does not stop the others; the key is always generated, even with nothing to encrypt): `~~HEX~~` (exactly `~~` + hex pairs +
  `~~`, else it is clear text), AES-256-GCM, key `<data_dir>/key.dat` generated if missing
  (0600, kept by the data dir cleanup). Only the value bytes change (comments/layout kept,
  atomic write, verified by re-decoding); read-only file = warn and continue. `${ENV}` refs
  are never rewritten. Vault auth secrets and sink `token`/`password` are encrypted the same way. `snmp-poller -encrypt`
  (key from `-config`'s data_dir or `-key`) encrypts a value by hand: the single argument,
  else the first line of piped stdin, else typed twice at the terminal without echo.
- **Vault**: top-level `vault:` (address, namespace, KV mount/version, prefix, auth
  token/approle/userpass/kubernetes). A device opts in with `snmp: { vault: true | <path> }`,
  default path `<prefix>/<device id>`. The KV secret's keys (same names as `snmp`, unknown =
  error) override the snmp block; read at every discovery (and each attempt while it fails),
  kept in memory only; on failure the previous credentials are kept. One login shared by all
  devices, renewed at 3/4 TTL or on 403. Hand-written HTTP client (`internal/vault`).
- **Global config**: worker thread count (default **250**), default poll interval, default discovery interval, timeouts, retries, data dir, stats interval.
- **Sinks** (`internal/sink`, config `sinks:`, device `sinks: [ids]`, default all, `[]` none):
  optional (none = data sent nowhere, warned at startup); `null` output removed. Types:
  `prometheus` = remote write 1.0 (hand-encoded protobuf + snappy, one TimeSeries per value,
  name `<prefix><key>`, default prefix `snmp_`, strings skipped, labels sorted) and `influxdb`
  = line protocol, gzip, `/api/v2/write?bucket=<database>&precision=ms` (InfluxDB 3 Core/
  Enterprise/Cloud, also 2.x), `Authorization: Token`; measurement = table or capability (for
  scalars), one line per row per batch (first timestamp), integers always `i`, backslashes
  not escaped (InfluxDB's own encoder rule), trailing ones dropped. Key = metric or
  `metric_rate`/`metric_volume`; `keys: {include, exclude}` regexes. `tags` = list of sources
  or `{name: source}`: device, address, index, table, capability, labels (table label+labels,
  not renamable), any discovery scalar (all values) or discovery column (rows of its
  capability's tables, `Batch.Columns`); default `[device, index, labels]`. Validation:
  Prometheus label names, a Prometheus name emitted by two tables, an InfluxDB tag equal to a
  field of its measurement, `time` tag, credentials in URL. Delivery: `Write` encodes in the
  poll worker and never blocks; per sink an intake goroutine cuts requests (`batch_size`,
  `flush_interval`) and a sender posts them in order. FIFO = memory (32MB) + disk buffer
  `<data_dir>/sinks/<id>/` (`disk_buffer`, default 1GB, `0`/`null` = none): disk records are
  always older than memory ones; down or memory full = spill to disk; full = oldest segment
  dropped. Retry (1s doubling to 30s) on network/5xx/429/401/403/404/408, drop on other 4xx.
  Segments `<seq>.seg` (header with CRC-32C, seq, samples, kind) + `cursor` file; torn tails
  truncated on open, corrupt records skipped. Close: `timeout` to send memory, rest to disk.
  Queues are shared by dir (registry): a reload's new sink takes over reading. `sinks/` is
  kept by the data dir cleanup; device id `sinks` is reserved. Per-sink stats line.
- **SNMP**: v1, v2c, v3. v3 supports context name / context engine ID, all security levels
  (noAuthNoPriv, authNoPriv, authPriv), all auth protocols (MD5, SHA, SHA224, SHA256, SHA384, SHA512)
  and all priv protocols (DES, AES, AES192, AES256, AES192C, AES256C). UDP and TCP transports,
  GETBULK or GETNEXT walks.
- **Discovery**: runs on the first poll of a device and then every hour by default
  (`discovery_interval`, configurable globally and per device). It detects capabilities, then
  collects slow-changing data: discovery scalars, model, and table columns (ifDescr, ifSpeed, ...)
  used for row labels, filtering and high-capacity selection. The result (capabilities, scalars,
  columns, rows, high-capacity rows) is the device's **on-disk cache** `data/<device_id>/discovery.json`,
  read back by every poll (not kept in memory); an unreadable cache triggers a rediscovery.
- **Value modes**: `raw` (value as-is), `rate` ((v2-v1)/(t2-t1), per second) and `volume` (v2-v1).
  Previous values for rate/volume are **stored on disk, not in memory**, in `data/<device_id>/state.json`, keyed by OID.
  Counter32 wraps are handled; Counter64 going backwards is treated as a reset.
  Device dirs of the data dir are cleaned on startup (files like key.dat and the `sinks` dir kept), and a device's
  state is wiped on each rediscovery.
- **Row based polling**: tables with an inclusive regex pattern list (`include`) matched against the
  row label (a discovery column, e.g. ifName) or the row index when no label is configured.
- **Logging**: configurable level, console and file. Default to console + file `logs/snmp-poller.log` with
  automatic rotation (size, backups, age, gzip) to `logs/snmp-poller-<time>.log.gz`.
  Format is always text (logfmt), not configurable (JSON was removed on purpose).
  Every timestamp is RFC 3339 with ms and an explicit zone; UTC by default, `logging.local_time: true`
  switches records and rotated file names to the local zone.
- **Useful logs**: no per-poll noise at info. A stats line every `stats_interval` (default 1m) with
  polls in progress, queued, succeeded, failed, skipped (overrun), discoveries, samples, durations.
  Per-device tracing (`trace: true` on a device) logs debug details for that device only, always
  tagged with `device`.
- **Never log credentials**. SNMP community strings are credentials. All secrets use the
  `config.Secret` type, which redacts itself in `String`, `GoString`, `LogValue` and JSON.
  Secrets may be given as `${ENV_VAR}` references. Vault errors carry only Vault's `errors`.
- **Docs**: `README.md` documents every option with samples for every scenario.

- **Robust GETs**: requests are chunked by `max_oids_per_request`, halved on `tooBig`; on
  `noSuchName` the offending OID is dropped (v1), exception varbinds are honoured, and the request is
  bisected when the agent gives no usable error index. One missing OID never hides the others.
- **Scheduling**: first polls spread over one interval; a device is never polled twice at once
  (overrun = `skipped`); graceful shutdown waits `shutdown_timeout` for in-flight polls.
- **Config strictness**: unknown YAML keys are errors; credentials are validated only when used;
  every ```yaml block in README.md must be valid (enforced by a test, see Testing notes).

## Testing notes

- `internal/testagent` (GoSNMPServer) has quirks: 0-based error index, `noSuchName` on v2c.
  Keep the GET fallbacks; do not "fix" tests around them.
- For a real-agent E2E without root: `apt-get download snmpd snmp libsnmp40t64 libsnmp-base`,
  `dpkg -x` each into a scratch dir, run `snmpd -C -c <conf> -I -smux` on a high port with
  `LD_LIBRARY_PATH`, `SNMP_PERSISTENT_DIR` and `MIBS=""` set. net-snmp supports every v3
  combination above (AES192/256 = Blumenthal), and contexts via `access ... <context> ...`.
- Never commit a sealed shipped file or a local `etc/conf.d/*.yaml` (`TestDefaultConfigFileNotSealed`,
  `.gitignore`). For E2E, copy `etc/` to a scratch dir, add `etc/conf.d/devices.yaml` there, and
  run the package (`go run ./cmd/snmp-poller` or a built binary), not `main.go` alone.
- Config tests never read local `etc/conf.d` files: they copy the shipped files to a temp dir
  (`shippedDir`). README ```yaml blocks: `# capabilities.d/<n>.yaml` = capability,
  `# conf.d/<n>.yaml` = include file (checked with the shipped main), `# prometheus.yml` =
  skipped (another program's file), else a main file.
- Sink tests decode requests with independent parsers (`protowire`, InfluxData's
  `line-protocol/v2`), test-only dependencies; poller tests inject fake sinks with
  `WithSinkFactory`.
- Real-backend E2E (user approved, auto mode blocks it otherwise): the dev box is **arm64**
  and /tmp is a small tmpfs, so put the linux-arm64 releases of Prometheus (with
  `--web.enable-remote-write-receiver`), InfluxDB 3 Core (`influxdb3 create token --admin`)
  and Grafana under `~/.cache/snmp-poller-e2e`. Kill servers with `pgrep -f "[p]attern"`,
  never a bare pattern (it matches the calling shell).
- `testagent.Agent.BulkRequests()` counts GETBULK requests (proves `walk: getnext`).
- No C compiler on the dev box, so `-race` is unavailable; use `go test -count=5 ./...` for flakes.

## Layout

- `cmd/snmp-poller` - entry point (flags, signals).
- `internal/config` - YAML schema, defaults, validation, `Secret`, encryption (`crypt.go`), Vault schema, formulas (`formula.go`).
- `internal/logging` - slog setup (console + rotating file), per-device level override.
- `internal/snmp` - gosnmp wrapper (version/auth/priv mapping, chunked GET, walks, v1 error handling).
- `internal/state` - on-disk previous-value store and delta/rate math.
- `internal/sink` - sinks: encoders (`encode.go`), HTTP client, FIFO and disk buffer (`queue.go`).
- `internal/vault` - Vault KV client (login, token reuse/renewal).
- `internal/poller` - scheduler, worker pool, discovery, polling, configuration reload, stats.
- `internal/testagent` - in-process SNMP agent used by integration tests (v1/v2c/v3).
- `internal/testconf` - test helper writing a config plus its capabilities.d to a temp dir.
- `etc/snmp-poller.yaml` - main configuration; `etc/conf.d/` - config files (examples only);
  `etc/capabilities.d/` - shipped capabilities.
