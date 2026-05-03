# Specter Long-Poll Command Delivery

## Context

Specter's C2 loop currently uses WorkManager periodic work (15-minute minimum enforced by Android) to poll `/api/poll`. Commands queue on the parent server and sit there for up to 15 minutes before the child checks in. This makes the command delivery loop useless for real pentesting work — sending a command and waiting 15 minutes for execution is not a C2, it's a batch job.

Long-polling fixes this by inverting the wait: the server holds the HTTP connection open until a command arrives, then responds immediately. The child reconnects instantly. Round-trip latency drops from up to 15 minutes to under 1 second.

---

## What Changes

### Parent — `ParentServer.kt`

**Add per-device command signals:**
```kotlin
private val commandSignals = ConcurrentHashMap<String, CompletableDeferred<Unit>>()
```

**`handlePoll` becomes a suspending function that waits:**
```kotlin
private suspend fun handlePoll(deviceId: String): Pair<String, Int> {
    if (deviceId.isEmpty()) return """{"error": "Missing device ID"}""" to 401

    // Ensure device has a signal slot
    commandSignals.getOrPut(deviceId) { CompletableDeferred() }

    // Wait up to 30s if no commands are queued
    if (pendingCommands[deviceId].isNullOrEmpty()) {
        val signal = commandSignals[deviceId]!!
        withTimeoutOrNull(30_000) { signal.await() }
    }

    // Replace signal for next poll cycle
    commandSignals[deviceId] = CompletableDeferred()

    val commands = pendingCommands[deviceId]?.toList() ?: emptyList()
    pendingCommands[deviceId]?.clear()
    val commandsJson = json.encodeToString(commands)
    return """{"commands":$commandsJson,"server_time":"${System.currentTimeMillis()}"}""" to 200
}
```

**`sendCommand` wakes the waiting poll immediately:**
```kotlin
fun sendCommand(deviceId: String, action: String, payload: String = "") {
    val cmd = Command(action = action, payload = payload)
    pendingCommands.getOrPut(deviceId) { mutableListOf() }.add(cmd)
    commandSignals[deviceId]?.complete(Unit)  // wake waiting poll
}
```

**`handleClient` must call `handlePoll` in a coroutine scope** (it already runs in `Dispatchers.IO` — verify the call site allows suspension).

---

### Child — `ChildSync.kt`

**Increase `READ_TIMEOUT` from 15s to 35s** so the connection outlives the server's 30s hold:
```kotlin
private const val READ_TIMEOUT = 35_000  // was 15_000
```

No other changes to `pollCommands()` — it already makes one GET to `/api/poll` and processes commands. The loop wrapper is in `ChildApplication`.

---

### Child — `ChildApplication.kt`

**Add a persistent poll loop:**
```kotlin
private var pollJob: Job? = null
private val pollScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

fun startPollLoop() {
    pollJob?.cancel()
    pollJob = pollScope.launch {
        var backoffMs = 5_000L
        while (isActive) {
            try {
                if (sync.serverUrl.isNotEmpty() && sync.deviceToken.isNotEmpty()) {
                    sync.pollCommands()
                    backoffMs = 5_000L  // reset on success
                } else {
                    delay(5_000)  // not configured yet, wait
                }
            } catch (e: CancellationException) {
                break
            } catch (e: Exception) {
                delay(backoffMs)
                backoffMs = minOf(backoffMs * 2, 30_000L)
            }
        }
    }
}
```

Call `startPollLoop()` in `loadConfigAndStart()` after the sync is configured.

---

### Child — `ConfigReceiver.kt`

After saving config and clearing the token, restart the poll loop so it picks up the new server URL:
```kotlin
ChildApplication.instance.startPollLoop()
```

---

## What Doesn't Change

- `/api/poll` endpoint path and HTTP method (GET)
- `PollResponse` JSON format `{"commands":[...],"server_time":"..."}`
- `executeCommand` and all command handlers
- WorkManager 15-min periodic sync (data upload + re-registration check — separate concern)
- All other endpoints (`/api/register`, `/api/sync`, `/api/result`)

---

## Data Flow

```
Operator taps LOCATE on S25
        │
        ▼
parentServer.locateDevice(deviceId)
  → pendingCommands[id].add(cmd)
  → commandSignals[id]?.complete(Unit)   ← wakes the waiting coroutine
        │
        ▼ (< 1ms)
handlePoll unblocks
  → returns {"commands":[{"action":"locate"}]}
        │
        ▼ (network RTT ~2-10ms on LAN)
Child pollCommands() receives response
  → executeCommand("locate")
  → pollCommands() called again immediately
```

Total latency: network RTT × 2 (~5-20ms on LAN).

---

## Error Handling

| Scenario | Behavior |
|---|---|
| Child disconnects mid-hold | Server coroutine cancelled by socket close; no state corruption |
| Server restarts | Child hits connection refused → backoff 5s → 10s → 30s cap → retries |
| Device not registered | `commandSignals` has no entry; `sendCommand` is a no-op for unknown IDs |
| Two polls from same device | Second poll gets a fresh `CompletableDeferred`; first one holds its own reference |
| Command arrives during reconnect gap | Queued in `pendingCommands`, delivered on next poll |

---

## Files Modified

| File | Change |
|---|---|
| `apps/specter/app/.../remote/ParentServer.kt` | Add `commandSignals`, make `handlePoll` suspending, wake signal in `sendCommand` |
| `apps/specter-child/app/.../sync/ChildSync.kt` | `READ_TIMEOUT` 15s → 35s |
| `apps/specter-child/app/.../ChildApplication.kt` | Add `startPollLoop()` with backoff loop, call from `loadConfigAndStart()` |
| `apps/specter-child/app/.../receiver/ConfigReceiver.kt` | Call `startPollLoop()` after reconfigure |
