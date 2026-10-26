# Host setup: Ubuntu VM on Windows 11 Pro (Hyper-V)

The core needs SCTP (N2/NGAP, S1AP) and TUN devices (UPF `ogstun`, UE `uesimtun0`).
A full Ubuntu VM provides both with the stock kernel.

## 1. Enable Hyper-V

PowerShell as Administrator, then reboot:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

## 2. Create the VM

1. Download the Ubuntu Server LTS ISO (24.04 or 26.04) from ubuntu.com.
2. Hyper-V Manager → New → Virtual Machine:
   - Generation 2
   - Memory: 8192 MB, dynamic memory off (4096 MB works for module 1)
   - Network: Default Switch
   - Disk: 50 GB
   - Install from the Ubuntu ISO
3. VM Settings:
   - Processor: 4 virtual processors
   - Security: Secure Boot on, template "Microsoft UEFI Certificate Authority"
4. Start the VM and install Ubuntu Server (enable OpenSSH server during install).

## 3. Check kernel support

Inside the VM:

```bash
sudo apt update && sudo apt -y upgrade
sudo modprobe sctp && lsmod | grep sctp
ls -l /dev/net/tun
ip -br addr
```

Expected: an `sctp` line in `lsmod`, and `/dev/net/tun` present as a character device.
