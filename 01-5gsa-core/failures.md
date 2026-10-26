# Module 1 failure scenarios

Each scenario: what was broken, what the UE and core report, what the capture shows, how to find the cause.
Captures are in [`pcap/`](pcap/). Wireshark setup as in [callflow.md](callflow.md)
(SCTP 38412 → NGAP, TCP 7777 → HTTP2, NAS-5GS null-cipher decoding on).

| # | Broken | Symptom on UE | 5GMM cause / NGAP cause | Capture |
|---|--------|---------------|-------------------------|---------|
| F1 | OPc on UE differs from the subscriber record | Authentication Reject, USIM considered invalid | #20 MAC failure | [f1-bad-opc.pcap](pcap/f1-bad-opc.pcap) |
| F2 | gNB broadcasts a PLMN the AMF does not serve | gNB never comes up, no cell for the UE | NGAP misc: unknown-PLMN-or-SNPN, TimeToWait 10 s | [f2-bad-plmn.pcap](pcap/f2-bad-plmn.pcap) |
| F3 | UE requests S-NSSAI SST 2, network serves only SST 1 | Registration Reject after authentication | #62 No network slices available | [f3-bad-sst.pcap](pcap/f3-bad-sst.pcap) |
| F4 | UE requests DNN `corp`, subscriber has only `internet` | Registered, but no PDU session | 5GMM #91 DNN not supported or not subscribed in the slice | [f4-bad-dnn.pcap](pcap/f4-bad-dnn.pcap) |
| F5 | UPF stopped, SMF has no PFCP association | Registered, PDU session rejected on every retry | 5GSM #38 Network failure | [f5-upf-down.pcap](pcap/f5-upf-down.pcap) |
| F6 | NRF down | | | to do |

---

## F1. Wrong OPc on the UE

**Break:** last hex digit of OPc changed on the UE side only (`...6183CA` → `...6183CB` in `config/bad-opc.yaml`).
The subscriber record in the UDR keeps the correct K/OPc.

**UE log (UERANSIM):**
```
[nas] Authentication Request received
[nas] Received SQN [875DE67A861F]
[nas] SQN-MS [000000000000]
[nas] AUTN validation MAC mismatch. expected [3458E649E5CF72C8] received [9FF9F75A9180B99F]
[nas] Sending Authentication Failure with cause [MAC_FAILURE]
[nas] Authentication Reject received
[nas] UE switches to state [5U3-ROAMING-NOT-ALLOWED]
[nas] UE switches to state [MM-DEREGISTERED/NO-SUPI]
```

**AMF log:**
```
[gmm] WARNING: [suci-0-250-99-0000-0-0-0000000001] Authentication failure [20]
[gmm] WARNING: Authentication failure(MAC failure)
[amf] WARNING: [suci-0-250-99-0000-0-0-0000000001] Authentication reject
[gmm] WARNING: [imsi-250990000000001] Failure in transaction; restoring context and transitioning to REGISTERED.
```

**Capture** (`f1-bad-opc.pcap`, 284 frames):

| Frame | Message | Note |
|-------|---------|------|
| 7 | InitialUEMessage, Registration Request | SUCI, null scheme |
| 117 | AMF → AUSF `POST /nausf-auth/v1/ue-authentications` | |
| 129 | AUSF → UDM `POST /nudm-ueau/v1/suci-.../generate-auth-data` | |
| 135 | UDM → UDR `GET .../authentication-subscription` | UDM builds the vector with the **correct** OPc |
| 158 | Authentication Request (RAND, AUTN) | |
| 159 | Authentication Failure, **5GMM cause #20 MAC failure** | UE computed XMAC from its own (wrong) OPc; XMAC ≠ MAC in AUTN |
| 160 | Authentication Reject | AMF does not retry |
| 281–283 | UEContextReleaseRequest (radioNetwork: radio-connection-with-ue-lost), Command, Complete | UE process stopped; gNB releases the N2 context |

There is no `5g-aka-confirmation` and no `auth-events` call: the procedure stops at the UE.

**Why:** in 5G-AKA the UE authenticates the network first (TS 33.501 §6.1.3.2). With a wrong OPc the
UE derives a different MAC, so AUTN fails verification on the UE. This is different from a wrong
RES*, which the network would detect.

| Failure cause from UE | Meaning | Network reaction |
|-----------------------|---------|------------------|
| #20 MAC failure | UE and network keys differ (K or OPc, or wrong subscriber profile) | Authentication Reject (Open5GS); the network may also ask for identity first |
| #21 Synch failure | keys are right, SQN out of range | UDM resynchronises SQN using AUTS, new challenge (seen in the first registration of module 1) |
| #26 non-5G authentication unacceptable | AMF separation bit in AMF field not set | |

**After the Reject** the UE sets 5U3 ROAMING NOT ALLOWED, deletes its 5G-GUTI and treats the USIM as
invalid until power cycle (TS 24.501, 5G AKA procedure, "authentication not accepted by the network"), which is the `MM-DEREGISTERED/NO-SUPI` state above.

**How to find it in production:**
1. AMF log or NAS trace: Authentication Failure with cause #20 for this SUPI.
2. Single subscriber or all? One SUPI → provisioning (K/OPc/AMF field in HSS/UDM, wrong SIM batch, wrong
   Transport Key). Many → OP/transport key or algorithm configuration on the UDM.
3. Compare the UDR record with the SIM vendor's output file for this IMSI.

**Fix:** correct OPc on the UE (or in the UDR), restart the UE.

---

## F2. gNB with a foreign PLMN

**Break:** gNB config with PLMN 001/01 (`config/bad-plmn-gnb.yaml`); AMF serves only 250/99
(`plmn_support` and `guami` in `amf.yaml`).

**gNB log:**
```
[sctp] SCTP connection established (127.0.0.5:38412)
[ngap] Sending NG Setup Request
[ngap] NG Setup procedure is failed. Cause: misc/unknown-PLMN-or-SNPN
```

**AMF log:**
```
[amf] INFO: gNB-N2 accepted[127.0.0.1]:48346 in ng-path module
[amf] WARNING: NG-Setup failure:
[amf] WARNING:     globalGNB_ID PLMN-ID is foreign
[amf] INFO: gNB-N2[127.0.0.1] connection refused!!!
```

**Capture** (`f2-bad-plmn.pcap`, N2 only, 13 frames). TS 38.413 §8.7.1 (NG Setup).

| Frame | Message | Note |
|-------|---------|------|
| 1–4 | SCTP INIT / INIT_ACK / COOKIE_ECHO / COOKIE_ACK | transport is fine, the association comes up |
| 5 | NGSetupRequest | Global gNB ID: PLMN **001/01** (pLMNIdentity `00f110`), gNB-ID 1; RAN node name UERANSIM-gnb-1-1-1; Supported TA list: TAC 1, broadcast PLMN 001/01, S-NSSAI SST 1; paging DRX v128 |
| 7 | NGSetupFailure | Cause **misc: unknown-PLMN-or-SNPN**, TimeToWait **v10s** |
| 8–9 | HEARTBEAT / ACK | SCTP stays up for a while after the failure |
| 10–12 | SHUTDOWN / ACK / COMPLETE | gNB process stopped |

**Why:** the AMF checks the PLMN in Global RAN Node ID and in the Supported TA list against its served
PLMNs. No match → NG Setup Failure. Nothing above N2 happens: there is no NG-C context, so the gNB does
not activate its cell and UEs cannot camp on it.

`pLMNIdentity` is BCD with nibbles swapped: `00 f1 10` = MCC 001, MNC 01 (2 digits, filler F).
For 250/99 it would be `52 f0 99`.

**How to find it in production:**
1. The gNB/OAM alarm is "NG link down" or "NG Setup failure"; the SCTP association itself may look healthy.
2. Read the cause in NGSetupFailure. `unknown-PLMN-or-SNPN` → compare PLMN in the gNB configuration
   with the AMF `plmn_support`/`guami`. Typical after a PLMN change, a MOCN/RAN-sharing rollout or a
   2-digit vs 3-digit MNC typo (`01` vs `001` gives a different pLMNIdentity).
3. Other causes seen at this step: TAC not served by the AMF, no common S-NSSAI.
4. TimeToWait tells the gNB how long to wait before retrying. UERANSIM does not retry; a production
   gNB keeps retrying after that interval.

**Fix:** set the gNB PLMN to 250/99 (or add the PLMN to the AMF), restart the gNB.

---

## F3. Requested slice not served

**Break:** UE config with SST 2 instead of SST 1 in `default-nssai`, `configured-nssai` and the session
(`config/bad-sst.yaml`). The AMF (`plmn_support.s_nssai`) and the subscriber only have SST 1.

**UE log:**
```
[nas] Security Mode Command received
[nas] Selected integrity[2] ciphering[0]
[rrc] RRC Release received
[nas] Initial Registration failed [?]
[nas] Handling Registration Reject abnormal case
[nas] UE switches to state [MM-DEREGISTERED/ATTEMPTING-REGISTRATION]
```

**AMF log:**
```
[gmm] ERROR: Cannot find Requested NSSAI [1]
[gmm] ERROR:     PLMN_ID[MCC:250 MNC:99]
[gmm] ERROR:     S_NSSAI[SST:2 SD:0xffffff]
[gmm] ERROR: [suci-0-250-99-0000-0-0-0000000001] gmm_handle_security_mode_complete() failed [62] in type [65]
[amf] WARNING: [suci-0-250-99-0000-0-0-0000000001] Registration reject [62]
```

**Capture** (`f3-bad-sst.pcap`, 117 frames, NRF heartbeats removed):

| Frame | Message | Note |
|-------|---------|------|
| 1 | InitialUEMessage, Registration Request | cleartext IEs only, **no Requested NSSAI yet** |
| 10–92 | AUSF / UDM / UDR | full 5G-AKA succeeds: the subscriber is valid |
| 76/77 | Authentication Request / Response | |
| 110 | Security Mode Command | |
| 111 | Security Mode Complete with the full Registration Request | **Requested NSSAI: SST 2 (URLLC)**, no SD |
| 112 | Registration Reject, **5GMM cause #62 No network slices available** | sent 0.4 ms after frame 111 |
| 113/115 | UEContextReleaseCommand (nas: normal-release) / Complete | |

**Why:** Requested NSSAI is a non-cleartext IE. With initial NAS message protection (TS 24.501), a UE
without a valid security context sends only cleartext IEs in the initial Registration Request and the full
message inside the NAS message container of Security Mode Complete. So the AMF can only evaluate the slice after authentication and NAS security,
which is why authentication succeeds and the reject comes right after Security Mode Complete.
Open5GS checks the requested S-NSSAI against its own `plmn_support` list; no match and no other allowed
slice → #62. In a full deployment the AMF also checks subscribed S-NSSAIs from UDM (`am-data`) and may ask
the NSSF.

`SD:0xffffff` in the AMF log means "no SD" (the reserved value used when SD is absent).

**UE side:** UERANSIM does not handle #62 as a specific cause (`failed [?]`, "abnormal case") and goes to
ATTEMPTING-REGISTRATION, so it will try again. A commercial UE handles #62 as a defined cause and uses the
Rejected NSSAI IE when the network includes it (Open5GS does not include it here).

**How to find it in production:**
1. Registration Reject #62 (or an Accept with Rejected NSSAI) for the subscriber.
2. Compare Requested NSSAI in Security Mode Complete with: AMF supported S-NSSAIs per TA, subscribed
   S-NSSAIs in UDM, NSSF policy. Watch the SD: SST 1 / SD 000001 and SST 1 without SD are different slices.
3. If many UEs fail: a slice was removed from the AMF/TA configuration or the gNB Supported TA list.
   If one UE: subscription or UE URSP/configured NSSAI.

**Fix:** use SST 1 on the UE, or provision SST 2 on the AMF and in the subscription.

---

## F4. DNN not subscribed

**Break:** UE session config with `apn: 'corp'` (`config/bad-dnn.yaml`). The subscriber has only DNN
`internet` in slice SST 1.

**UE log:**
```
[nas] Initial Registration is successful
[nas] Sending PDU Session Establishment Request
[nas] Configuration Update Command received
[nas] MM status received with cause [DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED]
```

**AMF log:**
```
[gmm] WARNING: [imsi-250990000000001] Ue requested DNN "corp" Not Supported OR Not Subscribed in the Slice
```
`smf.log` has no new lines: the request never reaches an SMF.

**Capture** (`f4-bad-dnn.pcap`, 249 frames, NRF heartbeats removed):

| Frame | Message | Note |
|-------|---------|------|
| 1–240 | Registration with 5G-AKA, Security Mode, Registration Accept | registration is fine |
| 155–177 | AMF → UDM → UDR `GET .../smf-select-data` → `200` | body: `{"subscribedSnssaiInfos":{"1":{"dnnInfos":[{"dnn":"internet","defaultDnnIndicator":true}]}}}` |
| 243 | Registration Complete + UL NAS Transport, PDU Session Establishment Request | PSI 1, request type initial, S-NSSAI SST 1, **DNN `corp`** |
| 245 | DL NAS Transport, **5GMM STATUS, cause #91** DNN not supported or not subscribed in the slice | answered by the AMF 0.8 ms later |
| 247–249 | UEContextReleaseRequest (radio-connection-with-ue-lost) / Command / Complete | UE process stopped |

No `nsmf-pdusession`, no PCF, no PFCP: the AMF stops the request itself.

**Why:** during registration the AMF reads the SMF Selection Subscription Data from UDM (subscribed DNNs per
S-NSSAI). When the UL NAS Transport carries a PDU Session Establishment Request for a DNN that is not in that
list for the requested S-NSSAI, the AMF does not select an SMF and returns 5GMM cause #91.

Open5GS answers with a **5GMM STATUS** message. As I read TS 24.501 (UL NAS TRANSPORT that the AMF cannot
forward), the expected answer is a DL NAS TRANSPORT that returns the 5GSM message to the UE with 5GMM cause
#91. The cause is the same, the message type differs; worth knowing when comparing vendors.

Compare with a DNN that is subscribed but not configured on the SMF/UPF: then the AMF forwards the request,
and the SMF rejects it with a 5GSM cause (#27 missing or unknown DNN) inside PDU Session Establishment Reject.
So the first question in troubleshooting is *who* rejected: 5GMM cause from the AMF vs 5GSM cause from the SMF.

**How to find it in production:**
1. UE: registered, no data. Trace the UL NAS Transport and the answer.
2. 5GMM #91 from the AMF → subscription (UDM `smf-selection-subscription-data` / `sm-data`) or a DNN typo
   in the device/APN profile (`internet` vs `internet.mnc099.mcc250.gprs` style FQDNs).
3. 5GSM #27 from the SMF → DNN missing in SMF/UPF configuration or DNS/NRF lookup for that DNN.

**Fix:** set the UE DNN to `internet`, or add DNN `corp` to the subscription and to SMF/UPF.

---

## F5. UPF down

**Break:** `sudo systemctl stop open5gs-upfd`, then start the UE with the normal config. Restored with
`sudo systemctl start open5gs-upfd`.

**UE log:**
```
[nas] Initial Registration is successful
[nas] Sending PDU Session Establishment Request
[nas] PDU Session Establishment Reject received [NETWORK_FAILURE]
[nas] Sending PDU Session Establishment Request
[nas] PDU Session Establishment Reject received [NETWORK_FAILURE]
...
```

**SMF log:**
```
LOCAL No Reponse. Give up! for step 1 type 5 peer [127.0.0.7]:8805
Retry association with peer failed
No UPFs are PFCP associated that are suited to RR
[imsi-250990000000001:1] No associated UPF
smf_npcf_smpolicycontrol_handle_create() failed
```
(`Reponse` is spelled that way in the Open5GS log.)

**Capture** (`f5-upf-down.pcap`, 180 frames; NRF heartbeats and the EPC SGW-C/SGW-U PFCP removed; only the
first two PDU attempts kept):

| Frame | Time | Message | Note |
|-------|------|---------|------|
| 1–4 | 22:01:09.9 | PFCP Heartbeat Request/Response, both directions, SMF ↔ UPF | last good exchange |
| 5–7 | 22:01:20.9, 23.4, 25.9 | PFCP Heartbeat Request SMF → UPF, no response | UPF already stopped; 3 tries 2.5 s apart |
| 8–13 | 22:01:28.4 … 44.4 | PFCP Association Setup Request, no response | SMF dropped the association and tries to set it up again |
| 14–77 | 22:01:45.71–45.75 | Registration, 5G-AKA, Security Mode, AM policy, Registration Accept | registration does not touch the UPF and works |
| 78 | 45.958 | Registration Complete + UL NAS Transport, PDU Session Establishment Request | PSI 1, DNN `internet`, SST 1 |
| 80–81 | 45.959 | AMF → SMF `POST /nsmf-pdusession/v1/sm-contexts` | |
| 82–93 | 45.961–45.967 | SMF → UDM `sm-data`, `sdm-subscriptions` | |
| 94 | 45.967 | SMF → AMF `201 Created` | the SM context is created before a UPF is chosen |
| 95–107 | 45.967–45.973 | SMF → PCF `POST sm-policies` → `201`; PCF → BSF `POST pcfBindings` → `201` | |
| 108–115 | 45.974–45.976 | SMF → PCF `POST sm-policies/5/delete`; PCF → BSF `DELETE pcfBindings/5` | rollback: no UPF to put the session on |
| 116–117 | 45.976 | SMF → AMF `POST /namf-comm/v1/ue-contexts/imsi-.../n1-n2-messages` | carries the N1 reject |
| 118 | 45.980 | DL NAS Transport, **PDU Session Establishment Reject, 5GSM cause #38 Network failure** | about 22 ms after the request; no Back-off timer IE |
| 122–161 | 46.810–46.832 | first retry, same sequence, same reject | |
| 162–164, 168–171 | 22:01:50.4 … 22:02:12.4 | PFCP Association Setup Request, no response | keeps trying while the UPF is down |
| 165–167 | 22:01:59.3 | UEContextReleaseRequest (radio-connection-with-ue-lost) / Command / Complete | UE process stopped |
| 172 | 22:02:12.449 | **PFCP Association Setup Response** UPF → SMF | UPF started again |
| 173–180 | 22:02:12.45 | Heartbeats both ways, a second Association Setup exchange | association is back |

In the full capture the UE retried 12 times between 22:01:45.96 and 22:01:56.73, mostly about 1.1 s apart.
Every attempt got the same reject. The capture stops before a new UE run, so a successful session after the
UPF restart is not in this file.

**Timing seen here (Open5GS defaults, as observed, not configured):** PFCP heartbeat every ~11 s; on no answer,
3 retries 2.5 s apart; then Association Setup Requests in groups of three 2.5 s apart with ~6 s between groups.
The SMF noticed the UPF loss at most ~19 s after it happened (one heartbeat interval plus the retries).

**Why:** the SMF can only create a session on a UPF it has a PFCP association with. With no associated UPF,
UPF selection fails. Open5GS does that step after it has already created the SM context and the SM policy, so
it rolls back the PCF policy and BSF binding and sends PDU Session Establishment Reject with 5GSM #38 through
the AMF. Nothing on N2 or N3 shows the problem: the gNB and the AMF are healthy, registration works, only the
N4 side is broken.

The reject has no Back-off timer IE, so the UE retries at its own pace. One UE every second is harmless in a
lab; in a network where a UPF dies under thousands of UEs, the same pattern becomes a signalling storm on the
AMF and SMF. That is why a back-off timer in the reject matters in production.

**How to find it in production:**
1. UEs register fine but get 5GSM #38 (or other 5GSM causes) on PDU session setup. The cause comes from the
   SMF, not the AMF (compare F4, where the AMF answers with 5GMM #91).
2. Check N4 first: PFCP heartbeats and association state between the SMF and each UPF. A heartbeat request
   with no response, followed by Association Setup Requests, means the UPF or the N4 path is down.
3. If the SMF has several UPFs, check which ones serve this DNN/S-NSSAI/TAI. One UPF down should move new
   sessions to the others; all of them down gives exactly this picture.
4. Sessions that were already up on the dead UPF lose user plane. That needs a separate check (GTP-U on N3,
   SMF session release/restoration behaviour); it was not tested here because no session existed.

**Fix:** start the UPF (`systemctl start open5gs-upfd`), check `upf.log` for why it stopped, and confirm the
PFCP association in `smf.log` before reattaching UEs.

