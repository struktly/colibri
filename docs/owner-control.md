# Optional process-owner drain control (Linux)

The default HTTP API, authentication, tools, engine supervision and model
selection are unchanged. This proposal adds no HTTP administration route,
root command, engine switcher or separate daemon.

An operator can opt the existing server into a private control directory with
--owner-control-dir DIRECTORY. The directory must already exist, be canonical
and absolute, belong to the server's effective UID, and grant no group/other
access. The server holds an exclusive owner lock and creates control.sock with
mode 0600. Linux peer credentials independently restrict connections to that
same UID. Unsupported platforms refuse this optional mode.

One newline-delimited JSON command is accepted per connection, at most 4096
bytes. No model, HTTP or host credentials are accepted. Responses carry
schema "colibri/owner-control/v1".

1. Send {"op":"status"} to obtain the current instance, process ID, engine
   identity, admission_closed, active and queued.
2. Send {"op":"drain","instance":"CURRENT_INSTANCE","lease":"64_LOWERCASE_HEX",
   "timeout_seconds":30}. The bound is zero to 300 seconds.
3. Send {"op":"resume","instance":"CURRENT_INSTANCE","lease":"SAME_LEASE"} to
   reopen admission. Another instance or lease cannot release it.

Drain atomically refuses new scheduler queue entries. Existing queued requests
continue in FIFO order and active work retains its context. The existing
watchdog's pause/resume cannot reopen an owner drain. Timeout never interrupts
or cancels work, and leaves admission closed. The same lease may inspect/wait
again; another lease is refused.

drained:true requires closed admission, no active or queued scheduler work,
a known live engine identity, no pending engine requests, and no unacknowledged
protocol-write failures. An empty pending map alone is insufficient: a failed
STOP/CANCEL/SUBMIT write can remove an entry without proving the engine stopped.
Only that request's terminal DONE/ERROR frame clears the unknown-work latch. Unknown backend
state returns drained:false. A receipt identifies this server instance and
engine generation. It is not evidence that the GPU has been released.

The lease is atomically persisted in the private directory. A restarted server
restores closed admission before serving HTTP requests and obtains a new
instance ID. Old receipts cannot mutate that new instance. Ordinary owner
control shutdown removes only its own socket; it keeps an outstanding lease.
A crash's stale socket is reclaimed only under the exclusive owner lock, after
confirming that it is an owned socket with no listener.

The controller must still verify the exact service/process identity, retain an
exclusive host-level engine transition, stop only after a valid drain receipt,
and establish that the old process/cgroup has exited before activating another
engine. This operation does not prevent an independently configured service
supervisor from restarting or preloading an engine. It does not close unrelated
ingress that bypasses this server or prove that other GPU consumers are idle.

## Deterministic verification

From the repository root:

~~~sh
PYTHONPATH=c:c/tests python3 -m unittest -v test_owner_control test_openai_server.SchedulerTest
~~~

These tests use scheduler contexts, private temporary Unix sockets and fake
engine identity; they never load a model or touch a service.
