# Module 2 failure scenarios

Each scenario: what was broken, what the UE and core report, what the capture shows, how to find the cause.
Captures are in [`pcap/`](pcap/). Wireshark setup as in [callflow.md](callflow.md).

| # | Broken | Symptom on UE | EMM cause | Capture |
|---|--------|---------------|-----------|---------|
| F1 | Open5GS sends a type 2 TAI list, srsUE misparses it and drops the GUTI | Attach works; after every idle period the UE is rejected and re-attaches with a new IP | #9 UE identity cannot be derived by the network | [f1-tai-list-type2.pcap](pcap/f1-tai-list-type2.pcap) |

---

## F1. TAI list type 2: UE cannot leave idle

Not a planned break: found on the first run with the default `tac: 1` in `mme.yaml`.

**Symptom.** Attach succeeds and traffic flows while the UE is connected. After ~40 s of inactivity
the eNB releases the UE. The next uplink packet triggers a Service Request, the network rejects it,
the UE attaches again and gets a new address (10.45.0.20 → .21 → .22 ...), and the default route in
the UE namespace disappears with the old `tun_srsue`. From the user side: ping works only if it never stops.

srsUE prints `Service Request successful.` for each attempt; that line only means the RRC connection
came up. The capture shows every one of them rejected.

**MME log:**

```
[emm] INFO: [] Service request
[emm] INFO: Service request : Not registered[]
[emm] WARNING: [] Failure in transaction; no context restoration.
```

The empty `[]` is the IMSI: the MME could not map the request to any UE context.

**Capture** (`f1-tai-list-type2.pcap`):

| Time (UTC) | InitialUEMessage | S-TMSI IE in S1AP | Answer |
|------------|------------------|-------------------|--------|
| 18:53:35 | Attach request (frame 2022) | n/a | Attach accept, GUTI M-TMSI 0xc00007f4 (2087) |
| 18:54:55–18:55:07 | Service request ×4 (3088, 3172, 3196, 3255) | **absent** | Service reject **#9** ×4 |
| 18:55:11 | Attach request (3324) | n/a | Attach accept, new M-TMSI (3383) |
| 18:56:58 | Service request (4724) | **absent** | Service reject #9 |
| 19:00:36, 19:00:40 | Service request ×2 (7489, 7561) | **absent** | Service reject #9 |
| 19:02:28 | Detach request, switch-off (9065) | **absent** | Service reject #9 |

Every InitialUEMessage has 5 IEs (eNB-UE-S1AP-ID, NAS-PDU, TAI, EUTRAN-CGI, RRC-Establishment-Cause).
A Service Request in EPS carries no identity of its own (only KSI, sequence number and short MAC,
TS 24.301 §8.2.25), so without the S-TMSI IE (TS 36.413 §9.1.7.1) the MME has nothing to look up.

**Following the identity back.**

1. The eNB copies S-TMSI into InitialUEMessage only if the UE sent it in RRCConnectionRequest.
2. The UE sends `ue-Identity: s-TMSI` only after NAS has stored a GUTI; otherwise it sends `randomValue`.
3. srsUE log with `--log.rrc_level=debug --log.nas_level=info`: `Received Attach Accept` is there,
   `Set ue-Identity` is not, and every RRCConnectionRequest has `"randomValue"`.
   The Detach Request also goes out with the IMSI instead of a GUTI; the Open5GS MME logs
   `Unknown EPS Mobile Identity Type [1]` for it.

So the UE received the GUTI but did not keep it.

**Root cause.** Attach Accept (frame 2087), bytes before the GUTI:

```
06 40 52 f0 99 00 01      TAI list: length 6, type 2 (TAIs of different PLMNs), number of elements 0 → 1 TAI
                          250/99, TAC 1
00 1d ...                 ESM message container
50 0b f6 52 f0 99 ...     GUTI
```

TS 24.301 §9.9.3.33 codes "number of elements" as one less than the real count. srsRAN 4G's NAS
parser (`liblte_mme_unpack_tracking_area_identity_list_ie` in `lib/src/asn1/liblte_mme.cc`) uses the
value as is. For a type 2 list with one TAI it reads zero elements, takes the next byte (`0x52`, the
first MCC octet) as a new list header, gets type 2 with 18 elements, hits the 16-entry limit and
returns an error before moving the read pointer past the IE. The ESM container and the GUTI are then
read from the wrong offset, `guti_present` stays false, and RRC never gets an S-TMSI.

Open5GS builds a type 2 list whenever a `tai` entry in `mme.yaml` has exactly one TAC
(`tac: 1` or `tac: [1]`); a range or several TACs give a type 1 or type 0 list.

**Workaround.** `tac: [1-2]` in `/etc/open5gs/mme.yaml`, restart `open5gs-mmed`. Attach Accept then
carries a type 1 list (one PLMN, consecutive TACs), which srsUE parses without overrunning.
Result (`m2-reference.pcap`, frame 1932): Service Request with S-TMSI mMEC 1, m-TMSI 0xc0000648,
accepted, same IP, and the srsUE log shows `Set ue-Identity to 0x1:0x3221227080`.

**How to recognise it in a live network.**

1. Repeated Attach for the same IMSI with a new IP every few minutes, Gx CCR-T before each new attach.
2. Service Reject #9 or Detach Reject on S1-MME, InitialUEMessage without S-TMSI from an idle UE.
3. One UE model or firmware only → UE-side NAS issue; all UEs → MME or S1 problem.
4. Compare the IEs in Attach Accept that the failing UE must parse with what the working UEs get
   (TAI list type, optional IEs) and check against the spec coding.
