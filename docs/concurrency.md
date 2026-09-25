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
