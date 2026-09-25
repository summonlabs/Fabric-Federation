# Concurrency and ownership audit

The runtime is deliberately small in its concurrency: one state mutex, one connection
registry, one accept thread and a bounded worker pool. This document records the audit that
was performed rather than leaving it implicit.

## Locks

| Lock | Guards | Held while |
| --- | --- | --- |
| `Impl::mutex` | evidence set, leases, observations, replay ledger, logical clock, incarnation, journal | a store operation is in progress |
| `Impl::sockets_mutex` | the weak references to live connection sockets | the registry is being read or updated |
| `Impl::queue_mutex` | the pending-connection queue | the queue is being read or updated |

## Lock order

`queue_mutex` and `sockets_mutex` are **never** held at the same time as `mutex`. The
code is written so that every path either takes the state mutex or a connection lock, never
both, which makes lock inversion structurally impossible rather than merely unlikely.

## Findings and the rules that follow

* **Self-deadlock / re-entry.** There is no path that takes `mutex` twice.
  `FederationCoordinator::handle_message` holds no lock and calls the public operations,
  which each take `mutex` once for the duration of the operation.
* **Read → write upgrade.** There is no reader/writer lock and no upgrade path; every
  operation takes the one mutex exclusively. Readers of `state()` therefore observe either
  the state before or the state after a concurrent submission, never a mix.
* **Callbacks under locks.** No callback, user code or virtual call is invoked while a lock
  is held. Explanations, states and lease values are copied out and returned by value.
* **Socket writes under locks.** The connection handshake assembles its welcome payload
  under the state mutex and **writes it after releasing it**, so a slow peer cannot stall
  other callers.
* **Joining workers while holding state.** `stop()` sets the stopping flag, closes the
  listener, joins the accept thread, shuts the live sockets down, wakes and joins the
  workers, and only then takes the state mutex to close the journal. No thread is joined
  while the state mutex is held.
* **Shutdown races.** A worker blocked in a read is released by `shutdown_both()` on a
  socket it still owns, so it observes an error, exits its loop and closes its own handle.
  The socket handle is atomic, so the concurrent access is well defined.
* **Iterator/reference invalidation.** Derived collections are built locally and moved into
  the state once; nothing holds a reference into a container that is concurrently mutated.
  The evaluator copies the member record it needs before it uses it.
* **Stale completion.** A worker that finishes after `stop()` began simply finds an empty
  queue and exits; there is no shared completion state to go stale.
* **Resource leaks.** Sockets are RAII; the journal is closed in `stop()` and in the
  destructor; the worker vector is cleared after joining; the pending queue is cleared after
  the workers exit. Every failure path in `spawn`/`accept` closes what it opened.
* **Bounded growth.** The pending-connection queue is bounded and a connection that arrives
  when it is full is closed rather than queued; the worker count is bounded and validated at
  creation; `kMaxConnections` bounds the accepted set.

## Slow-path observations

The transport has no connect timeout by design, so a connection attempt runs until the
operating system answers. On this machine a **refused** loopback connect costs about 2.05
seconds, because the SYN is retransmitted rather than answered with a reset (measured
directly; see `environment.md`). That cost is the platform's, not a wait introduced here,
and it is why the readiness helper in `tests/unit/test_protocol.cpp` performs the smallest
number of refused connects that still proves its contract. Nothing in the runtime or the
tests waits on a timer.

Per-case elapsed time is printed by the test harness (`[  OK  ] suite.case (12.3 ms)`). It
is a measurement, not a limit: no case is stopped, skipped or reclassified by it.

## Re-audit after the multiprocess and sanitizer fixes

The following changes were made after the first audit and were re-checked against it.

* **`Impl::decide_locked` now builds a per-subject index once per pass** instead of
  scanning the whole evidence set once per member. The index is a local; it is built and
  destroyed while the state mutex is held, and it touches no lock, no socket and no
  callback. Lock discipline is unchanged, and the change removed an O(members × artefacts)
  term that made the concurrency suite take minutes under instrumentation.
* **`MemberFabricRuntime::start_probe_listener` reuses the port it bound the first time**
  when the configuration asks for an ephemeral one. It is called from the member's control
  thread; if the listener is already open it returns immediately, and after a
  `stop_probe_listener` the probe thread has already been joined. There is no window in
  which the probe thread and a rebind overlap.
* **`concurrency.stopping_closes_live_connections_without_hanging` no longer sleeps.** It
  waited 20 ms and hoped the clients had connected; under AddressSanitizer that guess was
  wrong and the case failed for a reason that had nothing to do with the runtime. It now
  waits on a condition variable for a *fact* — that at least one client has completed a
  query — and the wait also ends when every client has finished, so a client that cannot be
  served reports a failure instead of hanging the suite. No timeout, no sleep, no watchdog.

## Tests that exercise this

`tests/unit/test_concurrency.cpp`:

* eight threads submitting 36 artefacts each — every submission is applied, nothing is lost,
  and the resulting membership is exactly what was submitted;
* eight threads asking 25 authority questions each — every question is granted exactly once
  and the replay ledger holds exactly 200 entries;
* four reader threads deriving state continuously while 40 members join — every read yields
  a consistent state and a non-zero digest;
* twenty start/stop cycles, each with a real client connect, ping and disconnect, checking
  that the listener is genuinely closed afterwards;
* six clients mid-conversation while the coordinator stops — no hang, no lost connection
  handling;
* twelve concurrent clients, each receiving its own welcome, with zero protocol errors.
