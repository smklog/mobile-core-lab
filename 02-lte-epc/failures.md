# Module 2 failure scenarios

Each scenario: what was broken, what the UE and core report, what the capture shows, how to find the cause.
Captures are in [`pcap/`](pcap/). Wireshark setup as in [callflow.md](callflow.md).

| # | Broken | Symptom on UE | EMM cause | Capture |
|---|--------|---------------|-----------|---------|
| F1 | Open5GS sends a type 2 TAI list, srsUE misparses it and drops the GUTI | Attach works; after every idle period the UE is rejected and re-attaches with a new IP | #9 UE identity cannot be derived by the network | [f1-tai-list-type2.pcap](pcap/f1-tai-list-type2.pcap) |
| F2 | OPc on the UE differs from the HSS record | `Network authentication failure`, no attach, retry every ~40 s | UE → MME Authentication failure #20 MAC failure, MME → UE Authentication reject | [f2-bad-opc.pcap](pcap/f2-bad-opc.pcap) |
| F3 | Subscriber deleted from the HSS | `Attach Reject. Cause = 08`, no retry | HSS: Experimental-Result 5001 DIAMETER_ERROR_USER_UNKNOWN → EMM #8 EPS and non-EPS services not allowed | [f3-no-subscriber.pcap](pcap/f3-no-subscriber.pcap) |
| F4 | PCRF stopped | RRC released, no attach; srsUE prints no reject | PGW: GTPv2 #100 Remote peer not responding; SGW → MME #103; EMM #17 + ESM #38 | [f4-pcrf-down.pcap](pcap/f4-pcrf-down.pcap) |
| F5 | SGW-C stopped | `Attach failed (attempt n/5)`, new attempt every ~30 s | none: S11 Create Session times out (3 sends, 2.5 s apart), UE context released without Attach Reject | [f5-sgw-down.pcap](pcap/f5-sgw-down.pcap) |
| F6 | PCRF installs a QCI 1 rule, eNB has no QCI 1 config | nothing: attach and ping work, traffic stays on the default bearer | no EMM cause: S1AP E-RAB Setup fails with not-supported-QCI-value, PGW Create Bearer Request times out | [m2-dedicated-bearer.pcap](pcap/m2-dedicated-bearer.pcap) |

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

---

## F5. SGW-C down (no answer on S11)

**Break:** `systemctl stop open5gs-sgwcd` (SGW-U, PGW and PCRF running), `.ctxt` deleted, normal UE config.
SGW-C started again after the test.

**UE:** `RRC Connected` → `RRC Connection Release` → `Attach failed (attempt 1/5)`, then 2/5, ...

**MME log:**

```
[mme] ERROR: GTP Timeout : IMSI[250990000000001] Message-Type[32] (../src/mme/mme-gtp-path.c:202)
```

Message type 32 is Create Session Request (TS 29.274 Table 6.1-1).

**Capture** (`f5-sgw-down.pcap`, 2582 frames, first attempt):

| Frame | Time (UTC) | Path | Message | Notes |
|------:|------------|------|---------|-------|
| 1177–1204 | 22:54:32.87–.96 | | Attach request, AIR/AIA, authentication, security mode, ULR/ULA | all normal |
| 1205 | 22:54:32.959 | MME → SGW-C :2123 | Create Session Request, seq 0x0e | |
| 1206 | 22:54:32.959 | kernel → MME | ICMP port unreachable | nothing listens on 127.0.0.3:2123 |
| 1236 | 22:54:35.462 | MME → SGW-C | Create Session Request, **same seq 0x0e** | retransmission after 2.5 s |
| 1265 | 22:54:37.965 | MME → SGW-C | Create Session Request, seq 0x0e | second retransmission |
| 1303 | 22:54:40.467 | MME → eNB | UEContextReleaseCommand, NAS-cause normal-release | 7.5 s after the first send; **no Attach Reject** |

Attempts at 22:54:32, 22:55:04 and 22:55:42 look the same.

**Observations:**

1. GTPv2 has its own reliability: the sender keeps the sequence number and retransmits on timer T3
   for N3 times (TS 29.274 §7.6). Here: 1 send + 2 retransmissions, 2.5 s apart, then the MME gives up.
   T3/N3 are configurable; a 7.5 s stall is visible to the user as a long "no service".
2. The MME ignores the ICMP port unreachable and waits for the timer anyway.
3. The MME releases the UE without an Attach Reject, so the UE has no cause; it treats the attempt
   as failed on its own timer and counts attempts (srsUE: 5).
4. Compare F4: there the SGW was alive, the PGW answered with a cause and the UE got a clean reject
   in under 10 ms. A dead node on S11 is slower and gives less information than a node that refuses.

**How to find it on a live network:**

1. Attach failures with no EMM cause and UE context release ~T3×N3 after ULA → look at S11.
2. Create Session Requests with repeated sequence numbers and no response → the SGW (or the path to it) is down.
3. In production the MME selects SGWs by DNS (TAI FQDN) and would mark the dead one and try another;
   GTP Echo Request/Response on S11 shows path failure before users do. This lab has one SGW and a static address.

## F6. eNB has no QCI 1 config: dedicated bearer rejected

**Break:** PCC rule ICMP → QCI 1, GBR 128 kbps on the subscriber (see [callflow §6](callflow.md#6-network-initiated-dedicated-bearer-gx--gbr-bearer-qci-1)),
srsENB with the stock `rb.conf` (`qci_config` has only QCI 7 and 9).

**UE:** `Network attach successful`, ping works. Nothing on the UE shows that a bearer was refused.

**Capture** (`m2-dedicated-bearer.pcap`, 2223 frames):

| Frame | Time, s | Path | Message | Notes |
|------:|--------:|------|---------|-------|
| 547/553 | 41.376 | PGW-C ↔ PCRF | Gx CCR-I / CCA | Charging-Rule-Install `internet-g1`, QCI 1, GBR 128 kbps |
| 564/567 | 41.411 | PGW-C → SGW-C → MME | Create Bearer Request | TFT ICMP UL/DL, QCI 1 |
| 579 | 41.671 | MME → eNB | E-RABSetupRequest + Activate dedicated EPS bearer context request | e-RAB 6, QCI 1 |
| 582 | 41.671 | eNB → MME | **E-RABSetupResponse, E-RABFailedToSetupList** | **radioNetwork not-supported-QCI-value**, 0.2 ms later |
| 618/619 | 43.914 | PGW-C → SGW-C → MME | Create Bearer Request, retransmission | the MME does not answer |
| 656/657 | 46.415 | | second retransmission | |
| 680–683 | 48.916 | SGW-C/PGW-C → SGW-U/PGW-U | PFCP Session Modification | Remove PDR/FAR for the bearer 6 rules, 7.5 s (T3×N3) after the first request |

There is **no Create Bearer Response** (GTPv2 type 96) in the capture. ICMP runs on the default bearer
(S1-U uplink TEID 0xa320).

**srsENB source** (`srsenb/src/stack/rrc/rrc_bearer_cfg.cc`, `bearer_cfg_handler::add_erab`):
a QCI not present in `qci_config` gives `QCI=%d not configured` and cause `not_supported_qci_value`.
A GBR above the `prioritized_bit_rate` of that QCI gives `invalid_qos_combination`.

**Fix:** add QCI 1 to `~/.config/srsran/rb.conf` (UM, like QCI 7):

```
qci_config = (
{
  qci = 1;
  pdcp_config = { discard_timer = 100; pdcp_sn_size = 12; }
  rlc_config = {
    ul_um = { sn_field_length = 10; };
    dl_um = { sn_field_length = 10; t_reordering = 45; };
  };
  logical_channel_config = { priority = 6; prioritized_bit_rate = 256; bucket_size_duration = 100; log_chan_group = 1; };
  enb_specific = { dl_max_retx_thresh = 32; };
},
{ qci = 7; ...
```

Restart the eNB. Result: [callflow §6](callflow.md#6-network-initiated-dedicated-bearer-gx--gbr-bearer-qci-1),
E-RAB 6 set up, Create Bearer Response cause 16, ICMP on TEID 0xf5e8.

**Observations:**

1. The failure is silent for the user: the default bearer carries the traffic, just without the GBR.
   On a live network this is how VoLTE calls end up on QCI 9 or drop, while data looks fine.
2. The MME got a clear S1AP cause but sent nothing back on S11. Open5GS leaves the PGW to time out
   (TS 23.401 §5.4.1 expects a Create Bearer Response with a reject cause).
3. The PCRF still believes the rule is active; no CCR-Update reports the failure.

**How to find it on a live network:**

1. Count E-RAB Setup failures per cause and QCI on the eNB/MME (KPI: E-RAB setup success rate by QCI).
2. `not-supported-QCI-value` → RAN QCI profile missing on that eNB, not a core problem.
3. GTPv2 Create Bearer Request retransmissions on S5/S11 with no response → look at S1 for the matching E-RAB.

