# Module 1 failure scenarios

Each scenario: what was broken, what the UE and core report, what the capture shows, how to find the cause.
Captures are in [`pcap/`](pcap/). Wireshark setup as in [callflow.md](callflow.md)
(SCTP 38412 → NGAP, TCP 7777 → HTTP2, NAS-5GS null-cipher decoding on).

| # | Broken | Symptom on UE | 5GMM cause / NGAP cause | Capture |
|---|--------|---------------|-------------------------|---------|
| F1 | OPc on UE differs from the subscriber record | Authentication Reject, USIM considered invalid | #20 MAC failure | [f1-bad-opc.pcap](pcap/f1-bad-opc.pcap) |
| F2 | Foreign PLMN | | | to do |
| F3 | S-NSSAI mismatch | | | to do |
| F4 | Wrong DNN | | | to do |
| F5 | UPF down | | | to do |
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
invalid until power cycle (TS 24.501 §5.4.1.3.7), which is the `MM-DEREGISTERED/NO-SUPI` state above.

**How to find it in production:**
1. AMF log or NAS trace: Authentication Failure with cause #20 for this SUPI.
2. Single subscriber or all? One SUPI → provisioning (K/OPc/AMF field in HSS/UDM, wrong SIM batch, wrong
   Transport Key). Many → OP/transport key or algorithm configuration on the UDM.
3. Compare the UDR record with the SIM vendor's output file for this IMSI.

**Fix:** correct OPc on the UE (or in the UDR), restart the UE.
