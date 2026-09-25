# Limitations

This list is part of the deliverable. Anything here is **not implemented** and is therefore
**not claimed**, in this repository, in the README, or anywhere else.

## Not implemented, not claimed

* **Consensus, quorum, agreement, Byzantine fault tolerance.** The coordinator is a single
  logical authority. Policy rules that count endorsements or distinct parties are
  deterministic evidence-counting rules evaluated by that one coordinator over the evidence
  it holds. They are not agreement, they are not quorum, and they do not tolerate a
  Byzantine coordinator. A coordinator that lies is not detected.
* **Cryptographic trust.** Transfers are unauthenticated. There is no signature, no key
  exchange, no certificate, no trust anchor, no message authentication code, and no
  transport encryption. The SHA-256 digests in this repository are integrity and determinism
  primitives, not authentication: anyone who can write the journal or open the socket can
  forge evidence that will verify.
* **Multi-host operation and real cross-site networking.** The transport is TCP over the
  IPv4 loopback interface, and the client refuses any host other than `127.0.0.1` or
  `localhost`. Nothing here has been run across hosts, across subnets, or across sites, and
  the partition rules have been exercised against loopback partitions produced by closing a
  listener — not against real network partitions.
* **Authentication and authorization of operators.** Anyone who can reach the control
  channel or the protocol port can drive the coordinator. There is no operator identity, no
  access control and no audit of who asked.
* **Global route computation, physical connectivity, identity providers, workload
  scheduling, site and inter-site runtimes.** These are member concerns and are explicitly
  outside this repository.
* **Failure detection.** There is no failure detector and no heartbeat timeout. Partition
  assessment evaluates the observation set the coordinator holds; it never decides on its
  own that a member is dead.
* **Automatic conflict resolution.** A disagreement is preserved. The runtime will not pick
  a winner by recency, by identity order, or by any other implicit rule.
* **Cross-federation composition.** One process serves one federation. Federations of
  federations are not modelled.
* **Arbitrary member counts and unbounded evidence.** Every bound in
  `include/fabric_federation/bounds.hpp` is real and enforced. The runtime is designed for
  federations of tens to hundreds of members, not thousands.

## Hardware and protocol claims

No CUDA, RDMA, InfiniBand, NVLink, switch/ASIC, vendor SDK or physical networking behaviour
is exercised, modelled or claimed. The only "network" in this repository is a loopback TCP
socket between processes on the machine that runs the tests.

## Evidence labels used in this repository

* **REAL** — implemented here and exercised by the test suite on the machine described in
  `environment.md`. `transport_description()` reports the transport as REAL loopback TCP
  and the tests assert that label rather than assuming it.
* **SYNTHETIC** — constructed fixture data. The reachability observations that tests feed to
  the coordinator by hand are synthetic in this sense; the observations produced by
  `MemberFabricRuntime::probe_peers` are not, they are real connection attempts.
* **UNSUPPORTED** — behaviour this runtime deliberately does not provide, listed above.
