# Mobile Core Lab

Home lab for mobile core networks: 5G SA, LTE/EPC, IMS/VoLTE, SS7/SIGTRAN and MPLS transport.
Every module has its configs, packet captures, call-flow walkthroughs and break/fix scenarios.

Radio is virtual only (UERANSIM, srsRAN over ZeroMQ). Nothing is transmitted over the air.
All subscriber data uses test values (PLMN 001/01, test IMSIs, example keys).

## Environment

- Host: Windows 11 Pro, Ubuntu Server 26.04 VM on Hyper-V (4 vCPU, 4 GB)
- Kernel requirements: SCTP (`modprobe sctp`) and TUN (`/dev/net/tun`)
- Setup guide: [docs/setup-hyperv.md](docs/setup-hyperv.md)
- Module 1 walkthrough (PDF, with diagrams): [docs/module1-5g-sa-guide.pdf](docs/module1-5g-sa-guide.pdf)

## Modules

| # | Module | Stack | Status |
|---|--------|-------|--------|
| 1 | [5G SA core and first registration](01-5gsa-core/) | Open5GS, UERANSIM | done |
| 2 | [LTE / EPC and Diameter](02-lte-epc/) | Open5GS EPC, srsRAN 4G (ZMQ) | in progress |
| 3 | IMS / VoLTE | Kamailio IMS, Open5GS | planned |
| 4 | Transport: MPLS / BGP / OSPF | containerlab, FRR | planned |
| 5 | SS7 / SIGTRAN / CAMEL, SGs | Osmocom | planned |
| 6 | Metrics, KPIs and analytics | Prometheus, Grafana, Python | planned |
| 7 | 5G NSA and SDN (optional) | srsRAN, Open5GS | planned |

## Module layout

```
NN-module/
  README.md      goal, diagram, component versions, run steps
  configs/       configs without secrets
  pcap/          captures
  callflow.md    procedures step by step, with frame numbers and 3GPP TS references
  failures.md    broken scenarios: what was broken, what the capture shows, how it was found
```
