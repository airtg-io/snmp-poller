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
- **Configuration**: YAML. Default file `etc/snmp-poller.yaml` (flag `-config`). `-check` validates and exits.
  The main file holds process settings, outputs, `vault` and devices only: **no SNMP metric
  definitions** (no profiles, no inline sets, no named credentials: reuse = YAML anchors). What to poll lives in `global.conf_dir`
  (default `conf.d`, relative to the main file, so `etc/conf.d`).
- **Capabilities**: one `*.yaml`/`*.yml` file per capability in conf_dir, named after the file.
  No `detect` = applies to every device; `detect: [oid...]` = applies when every OID subtree
  exists (one GETNEXT each, at discovery). Every capability found is polled unless the device
  lists it in `exclude` (only explicit exclusion removes one). Devices may override a table's
  `include` with `include: {table: [...]}`. Names are unique across capabilities; labels must
  come from the same capability. Shipped: `system` (always; sysDescr, sysObjectID, sysUpTime,
  sysContact, sysName, sysLocation as discovery scalars, plus sysUpTime polled every cycle),
  `interfaces` (always), `entity` (detected).
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
  defaulting to auth_password). Clear-text secrets are **encrypted in place** on startup once
  the config is valid (`Config.Seal`, not on `-check`): `~~HEX~~` (exactly `~~` + hex pairs +
  `~~`, else it is clear text), AES-256-GCM, key `<data_dir>/key.dat` generated if missing
  (0600, kept by the data dir cleanup). Only the value bytes change (comments/layout kept,
  atomic write, verified by re-decoding); read-only file = warn and continue. `${ENV}` refs
  are never rewritten. Vault auth secrets are encrypted the same way. `snmp-poller -encrypt`
  (key from `-config`'s data_dir or `-key`) encrypts a value by hand: the single argument,
  else the first line of piped stdin, else typed twice at the terminal without echo.
- **Vault**: top-level `vault:` (address, namespace, KV mount/version, prefix, auth
  token/approle/userpass/kubernetes). A device opts in with `snmp: { vault: true | <path> }`,
  default path `<prefix>/<device id>`. The KV secret's keys (same names as `snmp`, unknown =
  error) override the snmp block; read at every discovery (and each attempt while it fails),
  kept in memory only; on failure the previous credentials are kept. One login shared by all
  devices, renewed at 3/4 TTL or on 403. Hand-written HTTP client (`internal/vault`).
- **Global config**: worker thread count (default **250**), default poll interval, default discovery interval, timeouts, retries, data dir, stats interval.
- **Outputs**: configurable, multiple destinations, each device can target a subset (default: all).
  Only the `null` output exists for now (discards everything). Do not write SNMP data anywhere else yet.
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
  Device dirs of the data dir are cleaned on startup (files like key.dat kept), and a device's
  state is wiped on each rediscovery.
- **Row based polling**: tables with an inclusive regex pattern list (`include`) matched against the
  row label (a discovery column, e.g. ifName) or the row index when no label is configured.
- **Logging**: configurable level and sinks. Default to console + file `logs/snmp-poller.log` with
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
  every ```yaml block in README.md must be valid (enforced by a test): a complete main config
  checked against `etc/conf.d`, or a capability file when its first line is `# conf.d/<name>.yaml`.

## Testing notes

- `internal/testagent` (GoSNMPServer) has quirks: 0-based error index, `noSuchName` on v2c.
  Keep the GET fallbacks; do not "fix" tests around them.
- For a real-agent E2E without root: `apt-get download snmpd snmp libsnmp40t64 libsnmp-base`,
  `dpkg -x` each into a scratch dir, run `snmpd -C -c <conf> -I -smux` on a high port with
  `LD_LIBRARY_PATH`, `SNMP_PERSISTENT_DIR` and `MIBS=""` set. net-snmp supports every v3
  combination above (AES192/256 = Blumenthal), and contexts via `access ... <context> ...`.
- Running the poller with the shipped `etc/snmp-poller.yaml` encrypts its example credentials
  with a local `data/key.dat`: never commit that (`TestDefaultConfigFileNotSealed` fails). Run
  with a copy (`-config`) and run the package (`go run ./cmd/snmp-poller`), not `main.go` alone.
- `testagent.Agent.BulkRequests()` counts GETBULK requests (proves `walk: getnext`).
- No C compiler on the dev box, so `-race` is unavailable; use `go test -count=5 ./...` for flakes.

## Layout

- `cmd/snmp-poller` - entry point (flags, signals).
- `internal/config` - YAML schema, defaults, validation, `Secret`, encryption (`crypt.go`), Vault schema.
- `internal/logging` - slog setup (console + rotating file), per-device level override.
- `internal/snmp` - gosnmp wrapper (version/auth/priv mapping, chunked GET, walks, v1 error handling).
- `internal/state` - on-disk previous-value store and delta/rate math.
- `internal/output` - `Output` interface, registry, `null` output.
- `internal/vault` - Vault KV client (login, token reuse/renewal).
- `internal/poller` - scheduler, worker pool, discovery, polling, stats.
- `internal/testagent` - in-process SNMP agent used by integration tests (v1/v2c/v3).
- `internal/testconf` - test helper writing a config plus its conf.d to a temp dir.
- `etc/snmp-poller.yaml` - default configuration; `etc/conf.d/` - shipped capabilities.
