# Module 2 failure scenarios

Each scenario: what was broken, what the UE and core report, what the capture shows, how to find the cause.
Captures are in [`pcap/`](pcap/). Wireshark setup as in [callflow.md](callflow.md).

| # | Broken | Symptom on UE | EMM cause | Capture |
|---|--------|---------------|-----------|---------|
| F1 | Open5GS sends a type 2 TAI list, srsUE misparses it and drops the GUTI | Attach works; after every idle period the UE is rejected and re-attaches with a new IP | #9 UE identity cannot be derived by the network | [f1-tai-list-type2.pcap](pcap/f1-tai-list-type2.pcap) |
| F2 | OPc on the UE differs from the HSS record | `Network authentication failure`, no attach, retry every ~40 s | UE → MME Authentication failure #20 MAC failure, MME → UE Authentication reject | [f2-bad-opc.pcap](pcap/f2-bad-opc.pcap) |
| F3 | Subscriber deleted from the HSS | `Attach Reject. Cause = 08`, no retry | HSS: Experimental-Result 5001 DIAMETER_ERROR_USER_UNKNOWN → EMM #8 EPS and non-EPS services not allowed | [f3-no-subscriber.pcap](pcap/f3-no-subscriber.pcap) |
| F4 | PCRF stopped | RRC released, no attach; srsUE prints no reject | PGW: GTPv2 #100 Remote peer not responding; SGW → MME #103; EMM #17 + ESM #38 | [f4-pcrf-down.pcap](pcap/f4-pcrf-down.pcap) |

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

---

## F2. Wrong OPc on the UE

**Break:** last hex digit of OPc changed in a copy of the UE config only
(`...6183CA` → `...6183CB` in `ue-bad-opc.conf`); the HSS keeps the correct K/OPc.
The saved NAS context (`~/.config/srsran/.ctxt`) was deleted first; with it the UE attaches with a
known GUTI and the MME skips authentication, so the bad key is never tested.

**UE:** `Warning: Network authentication failure`, RRC released, new attempt about every 40 s.

**MME log:**

```
[emm] WARNING: Authentication failure (../src/mme/emm-sm.c:1140)
[emm] WARNING: Authentication failure(MAC failure) (../src/mme/emm-sm.c:1148)
```

**Capture** (`f2-bad-opc.pcap`, 2658 frames, one cycle of four shown):

| Frame | Path | Message | Notes |
|------:|------|---------|-------|
| 1369 | eNB → MME | Attach request | identity IMSI (no stored GUTI) |
| 1370/1382 | MME ↔ HSS | AIR/AIA (S6a) | HSS builds the vector with the correct OPc, Result-Code success |
| 1383 | MME → UE | Authentication request | RAND, AUTN |
| 1385 | UE → MME | **Authentication failure, EMM cause #20 MAC failure** | 41 ms later |
| 1386 | MME → UE | **Authentication reject** | |
| 1387/1389 | MME ↔ eNB | UEContextReleaseCommand/Complete | |

Attempts at 22:34:06, 22:34:46, 22:35:24 and 22:35:29 UTC. There is no ULR, no Create Session and
no Gx: the procedure stops before the MME tells the HSS where the UE is. Stopping srsUE sent a
switch-off Detach with the IMSI (frame 2466), answered with #9 like in F1, and one more attach
attempt followed at once.

**Why:** in EPS-AKA the UE checks the network first (TS 33.401 §6.1.1, TS 33.102 §6.3.3).
It recomputes MAC from RAND, SQN and its own K/OPc; with a different OPc the result does not match
the MAC in AUTN and the UE answers with Authentication Failure #20 instead of a RES (TS 24.301 §5.4.2.6).
The MME never compares RES with XRES here. The opposite case, a correct AUTN but a wrong RES
from the UE, ends with Authentication Reject without a failure message from the UE.

**Same fault in 5G (Module 1 F1):** 5GMM #20 MAC failure, the AUSF and UDM take the place of the HSS.

**How to find it on a live network:**

1. Many `Authentication failure #20` for one IMSI, none for others → SIM or HSS provisioning of that subscriber (K, OPc, AMF field, wrong batch).
2. #20 for a whole IMSI range at once → HSS/AuC change (OP/OPc or algorithm configuration).
3. #21 synch failure instead of #20 → keys are right, SQN is out of range; the HSS resynchronises with AUTS.

---

## F3. Subscriber not in the HSS

**Break:** `dbctl remove 250990000000001` (the HSS and the 5G UDR share the MongoDB `subscribers`
collection), `.ctxt` deleted, normal `ue.conf`. Restored afterwards with `dbctl add` and the same K/OPc.

**UE:** `Received Attach Reject. Cause= 08`, RRC released, **no further attempts**.

**Capture** (`f3-no-subscriber.pcap`, 1440 frames):

| Frame | Path | Message | Notes |
|------:|------|---------|-------|
| 807 | eNB → MME | Attach request | identity IMSI 250990000000001 |
| 808 | MME → HSS | AIR (S6a) | |
| 814 | HSS → MME | AIA, **Experimental-Result-Code 5001 DIAMETER_ERROR_USER_UNKNOWN** | no Result-Code AVP, no vector; 9 ms |
| 815 | MME → UE | **Attach reject, EMM #8** EPS services and non-EPS services not allowed | 62 ms after the Attach Request |
| 816/818 | MME ↔ eNB | UEContextReleaseCommand/Complete | |
| 1259 | eNB → MME | Detach request (switch-off, IMSI) on srsUE stop | answered #9, the MME has no context |

No Authentication Request is sent: without a subscriber record there is no vector.

**Why no retry:** #8 tells the UE to consider the USIM invalid for EPS and non-EPS services until it is
switched off or the USIM is replaced (TS 24.301 §5.5.1.2.5). Compare F2: after #20 the UE kept trying.
The Diameter-to-NAS mapping (5001 → #8) follows TS 29.272 Annex A.

**Diameter detail:** S6a errors that are specific to 3GPP come back in `Experimental-Result`
(Vendor-Id 10415 + Experimental-Result-Code), not in `Result-Code`. A filter on `diameter.Result-Code`
alone misses them; use `diameter.Experimental-Result-Code`.

**How to find it on a live network:**

1. Attach Reject #8 right after AIR, with no Authentication Request in between → HSS does not know the IMSI.
2. One IMSI → provisioning (not created, deleted, typo in IMSI). A whole range → missing IMSI range
   or routing: in roaming, the DEA/DRA may route the AIR to the wrong HSS.
3. Check the HSS/HLR record and the Diameter routing table for the IMSI prefix.

---

## F4. PCRF down (no Gx peer)

**Break:** `systemctl stop open5gs-pcrfd`, `.ctxt` deleted, normal UE config. PCRF started again after the test.

**UE:** RRC connected, then `RRC Connection Release`, back to idle. srsUE does not print the reject;
the capture shows it.

**SMF (PGW-C) log:**

```
[smf] ERROR: No Gx Diameter Peer (../src/smf/s5c-handler.c:160)
[diam] INFO: CONNECTED TO 'pcrf.localdomain' (SCTP,soc#10)      <- after the PCRF was started again
```

**Capture** (`f4-pcrf-down.pcap`, 1777 frames, first attempt):

| Frame | Path | Message | Notes |
|------:|------|---------|-------|
| 150, 512, 872, ... | PGW-C → PCRF :3868 | SCTP INIT → ABORT | Diameter peer reconnect every ~30 s; port closed |
| 976–1003 | | Attach request, AIR/AIA, authentication, security mode, ULR/ULA | all normal: the HSS side is fine |
| 1004 | MME → SGW-C | Create Session Request | |
| 1005–1006 | SGW-C ↔ SGW-U | PFCP Session Establishment | SGW-U session created |
| 1007 | SGW-C → PGW-C | Create Session Request | |
| 1008 | PGW-C → SGW-C | **Create Session Response, cause #100 Remote peer not responding** | 3 ms; no CCR is sent at all |
| 1009 | SGW-C → MME | **Create Session Response, cause #103 Conditional IE missing** | the cause changed on the way |
| 1010 | MME → UE | **Attach reject, EMM #17 Network failure + PDN connectivity reject, ESM #38 Network failure** | |
| 1011/1013 | MME ↔ eNB | UEContextReleaseCommand/Complete | |

Second attempt at 22:48:28 (frames 1553–1590) is identical.

**Observations:**

1. The PGW fails fast and says why (#100, TS 29.274 §8.4): with no Diameter connection to the PCRF
   it does not even try a CCR.
2. **The cause is not passed through.** The SGW-C turns #100 from the PGW into #103 toward the MME.
   Looking only at S11 (or at MME counters per cause) points at a malformed message instead of a dead
   PCRF. Always follow the cause hop by hop: S11 → S5 → Gx.
3. The SGW-U session created in 1005–1006 is not deleted in this capture (no PFCP Session Deletion
   on Sxa for either attempt). Worth checking SGW-U session counts after this kind of failure.
4. In 5G the same fault (no PCF) shows up as a failed Npcf_SMPolicyControl_Create and 5GSM #38 (compare Module 1 F5 for the UPF).

**How to find it on a live network:**

1. Attach Reject #17/#38 after a successful ULA → the problem is on S11/S5/Gx, not on S6a.
2. Create Session Response cause on S5 (not only S11), then Gx: CCR present? CCA Result-Code?
3. No CCR at all and Diameter peer down in the PGW (SCTP INIT/ABORT or DWR timeouts to the PCRF/DRA)
   → PCRF or DRA unreachable. Operators often configure Gx failover (secondary PCRF, or local policy
   "continue without PCRF"); this lab has none.
