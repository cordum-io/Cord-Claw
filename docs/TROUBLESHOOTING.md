# Cord-Claw Troubleshooting

## Daemon won't start

**Symptom**: `cordclaw-daemon` exits immediately or prints `bind: address already in use`.

**Fix**: Another process is using port 19090. Check with:

```bash
lsof -i :19090    # macOS/Linux
netstat -ano | findstr 19090  # Windows
```

Kill the conflicting process or change the daemon port:

```bash
cordclaw-daemon --port 19091
```

Update the plugin config to match the new port.

## Plugin can't reach daemon

**Symptom**: OpenClaw actions fail with `ECONNREFUSED` or `connection refused` errors.

**Fix**:
1. Verify the daemon is running: `curl http://localhost:19090/health`
2. Check the daemon is bound to the correct interface (default: `127.0.0.1`)
3. Ensure no firewall is blocking localhost connections
4. If using Docker, ensure the plugin and daemon share the same network namespace

## All actions are being denied

**Symptom**: Every tool call returns `DENY` regardless of risk level.

**Possible causes**:
1. **Wrong profile**: You may be running the `strict` profile. Check with `curl http://localhost:19090/status`
2. **Safety Kernel unreachable + empty cache**: If the kernel is down and the daemon has no cached decisions, it fails closed (denies novel actions). Check kernel connectivity: `curl http://localhost:19090/health` and look for `kernel_connected: false`
3. **Policy override error**: A malformed custom policy file can cause all-deny behavior. Remove `--policy-override` flag and test again.

## Cache not working (every request is slow)

**Symptom**: Response times are consistently >50ms even for repeated identical actions.

**Fix**:
1. Check cache stats: `curl http://localhost:19090/status` — look at `cache_hits` and `cache_misses`
2. Verify cache is enabled (default: on). It can be disabled with `--cache-disabled`
3. Cache keys include all risk tags. If risk tags vary between identical actions, cache won't hit. Check your tag inference.

## Safety Kernel connection drops

**Symptom**: Daemon logs show `gRPC connection lost` or `circuit breaker open`.

**Fix**:
1. Check kernel is running and reachable from the daemon host
2. If using mTLS, verify certificates haven't expired: `openssl x509 -in cert.pem -noout -enddate`
3. The circuit breaker opens after 5 consecutive failures and resets after 30 seconds. During this time, only cached decisions are served.
4. For local development, ensure the Cordum stack is running: `docker compose ps`

## Install script fails

**Symptom**: `setup/install.sh` exits with errors during Docker Compose bring-up.

**Fix**:
1. Ensure Docker is running: `docker info`
2. Check required ports are free: 19090 (daemon), 50051 (Safety Kernel), 6379 (Redis), 4222 (NATS)
3. On macOS with Apple Silicon, ensure Docker is configured for ARM64
4. Try a clean start: `docker compose -f setup/docker-compose.yml down -v && ./setup/install.sh`

## Plugin not intercepting actions

**Symptom**: OpenClaw actions execute without policy checks.

**Fix**:
1. Verify the plugin is registered in OpenClaw's gateway config
2. Check plugin logs for registration errors
3. Ensure the `before_tool_execution` hook is supported by your OpenClaw version
4. Test the plugin directly: `npm test` in the `plugin/` directory

## Getting help

- Open an issue: https://github.com/cordum-io/Cord-Claw/issues
- Discussions: https://github.com/cordum-io/Cord-Claw/discussions
- Security issues: security@cordum.io (see [SECURITY.md](../SECURITY.md))
