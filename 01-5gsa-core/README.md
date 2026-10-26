# Module 1. 5G SA core and first registration

**Goal:** Open5GS 5GC (AMF, SMF, UPF, NRF, AUSF, UDM, UDR, PCF, NSSF, BSF) with UERANSIM gNB and UE.
Register the UE, establish a PDU session, ping through `uesimtun0`.

**Captures:** N2 (NGAP/SCTP), N1 NAS (NEA0/NIA0), N4 (PFCP), N3 (GTP-U), SBI (HTTP/2).

**Walkthroughs:** Registration with 5G-AKA, PDU Session Establishment, Service Request, Deregistration.

**Failure scenarios:** wrong K/OPc, foreign PLMN, S-NSSAI mismatch, wrong DNN, UPF down, NRF down.

Status: environment setup.
