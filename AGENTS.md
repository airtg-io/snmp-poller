# AIrtg SNMP Poller - agent memory

Free and open source (GPLv3, see `LICENSE`) SNMP poller for AIrtg, written in Go.
This file is the project's agent memory: every feature and hard requirement lives here.
Keep it current when features are added or changed. User-facing docs live in `README.md`.

## Hard requirements (do not regress)

- **Language**: Go only. Build: `go build ./cmd/snmp-poller`. Test: `go test ./...`. Lint: `go vet ./...` and `gofmt -l .`.
- **Configuration**: YAML. Default file `etc/snmp-poller.yaml` (flag `-config`). `-check` validates and exits.
- **Global config**: worker thread count (default **250**), default poll interval, default discovery interval, timeouts, retries, data dir, stats interval.
- **Outputs**: configurable, multiple destinations, each device can target a subset (default: all).
  Only the `null` output exists for now (discards everything). Do not write SNMP data anywhere else yet.
- **SNMP**: v1, v2c, v3. v3 supports context name / context engine ID, all security levels
  (noAuthNoPriv, authNoPriv, authPriv), all auth protocols (MD5, SHA, SHA224, SHA256, SHA384, SHA512)
  and all priv protocols (DES, AES, AES192, AES256, AES192C, AES256C). UDP and TCP transports.
- **Discovery**: runs on the first poll of a device and then every hour by default
  (`discovery_interval`, configurable globally and per device). Discovery collects slow-changing data:
  system scalars (sysDescr, sysObjectID, sysName are always collected), model, and table columns
  such as ifName/ifDescr used for row labels and row filtering. Saved to `data/<device_id>/discovery.json`.
- **Value modes**: `raw` (value as-is), `rate` ((v2-v1)/(t2-t1), per second) and `volume` (v2-v1).
  Previous values for rate/volume are **stored on disk, not in memory**, in `data/<device_id>/state.json`.
  Counter32 wraps are handled; Counter64 going backwards is treated as a reset.
  The data dir is cleaned on startup, and a device's state is wiped on each rediscovery.
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
  Secrets may be given as `${ENV_VAR}` references.
- **Docs**: `README.md` documents every option with samples for every scenario.

- **Robust GETs**: requests are chunked by `max_oids_per_request`, halved on `tooBig`; on
  `noSuchName` the offending OID is dropped (v1), exception varbinds are honoured, and the request is
  bisected when the agent gives no usable error index. One missing OID never hides the others.
- **Scheduling**: first polls spread over one interval; a device is never polled twice at once
  (overrun = `skipped`); graceful shutdown waits `shutdown_timeout` for in-flight polls.
- **Config strictness**: unknown YAML keys are errors; credentials are validated only when used;
  every ```yaml block in README.md must be a complete valid config (enforced by a test).

## Testing notes

- `internal/testagent` (GoSNMPServer) has quirks: 0-based error index, `noSuchName` on v2c.
  Keep the GET fallbacks; do not "fix" tests around them.
- For a real-agent E2E without root: `apt-get download snmpd snmp libsnmp40t64 libsnmp-base`,
  `dpkg -x` each into a scratch dir, run `snmpd -C -c <conf> -I -smux` on a high port with
  `LD_LIBRARY_PATH`, `SNMP_PERSISTENT_DIR` and `MIBS=""` set. net-snmp supports every v3
  combination above (AES192/256 = Blumenthal), and contexts via `access ... <context> ...`.
- No C compiler on the dev box, so `-race` is unavailable; use `go test -count=5 ./...` for flakes.

## Layout

- `cmd/snmp-poller` - entry point (flags, signals).
- `internal/config` - YAML schema, defaults, validation, profile/credential resolution, `Secret`.
- `internal/logging` - slog setup (console + rotating file), per-device level override.
- `internal/snmp` - gosnmp wrapper (version/auth/priv mapping, chunked GET, walks, v1 error handling).
- `internal/state` - on-disk previous-value store and delta/rate math.
- `internal/output` - `Output` interface, registry, `null` output.
- `internal/poller` - scheduler, worker pool, discovery, polling, stats.
- `internal/testagent` - in-process SNMP agent used by integration tests (v1/v2c/v3).
- `etc/snmp-poller.yaml` - default configuration.
