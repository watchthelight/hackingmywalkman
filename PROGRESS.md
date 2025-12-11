# Sony NW-A306 Walkman - Native Linux Boot Chain Reverse Engineering

## Project Status: IN PROGRESS
**Last Updated:** 2025-12-11

---

## Device Information

| Property | Value |
|----------|-------|
| Model | Sony NW-A306 |
| Codename | icx1301 |
| SoC | Qualcomm QCS2290 (SCUBAPIIOT) |
| CPU | 4-core ARM64 @ 2.016GHz |
| RAM | 3.7GB |
| Storage | 32GB eMMC (mmcblk0) |
| Android Version | 14 |
| Kernel | 4.19.157-perf+ |
| Build ID | 3.02.01 |
| Security Patch | 2025-04-05 |
| Bootloader | LOCKED |
| Verified Boot | GREEN |
| OEM Unlock Allowed | YES (sys.oem_unlock_allowed=1) |

---

## Goal

Run Ubuntu/Linux **natively on bare metal** (no Android, no proot) as a headless server with SSH access.

**User Preferences:**
- Risk Tolerance: FULL SEND - Accept brick risk
- Hardware Access: SOFTWARE ONLY - No physical modifications
- Target: HEADLESS SERVER - No display needed, SSH access

---

## What Has Been Completed

### Phase 1: Termux Microserver Setup (COMPLETED)

Before native Linux, we set up Termux as an intermediate solution:

1. **Installed Termux from F-Droid**
   - SSH server on port 8022 (password: 132005)
   - nginx on port 8080
   - tmux, python, nodejs, git

2. **Configured Persistence**
   - Installed Termux:Boot for autostart
   - Created boot script at `~/.termux/boot/start-services.sh`
   - Configured fullscreen mode, disabled screen sleep

3. **Disabled Bloatware**
   - Disabled 26 unnecessary apps

4. **Set up ADB Port Forwarding**
   ```bash
   adb forward tcp:8022 tcp:8022  # SSH
   adb forward tcp:8080 tcp:8080  # nginx
   ```

---

## Attack Vectors Attempted

### STEP 1: EDL/Fastboot Mode Access (COMPLETED)

#### EDL Mode - BLOCKED
```bash
adb reboot edl  # Command ignored/rejected by device
```
- Device does not enter EDL mode via ADB
- Would need hardware test point (not documented for this device)
- Requires signed Firehose programmer for QCS2290 (not publicly available)

#### Fastboot Mode - PARTIAL SUCCESS
```bash
adb reboot bootloader  # Works!
```
- Device enters fastboot mode successfully
- Installed "Google, Inc. - Android Bootloader Interface" driver

**Fastboot Findings:**
- Product: icx1301
- Variant: QCS EMMC
- Bootloader: LOCKED
- Secure Boot: YES
- Current Slot: b
- Boot Partition Size: 96MB

**Fastboot Commands - ALL BLOCKED:**
```bash
fastboot flashing unlock     # FAIL: unknown command
fastboot oem unlock          # FAIL: unknown command
fastboot oem unlock-go       # FAIL: unknown command
fastboot reboot              # FAIL: unknown command (!)
fastboot continue            # FAIL: unknown command
```

Sony has removed nearly all standard fastboot commands from the ABL (Android Boot Loader).

### STEP 2: EDL Partition Dump (BLOCKED)

Cannot proceed without:
- Signed Firehose programmer for QCS2290
- Hardware access to EDL test points

### STEP 3: Kernel Exploitation (IN PROGRESS)

#### Kernel Configuration Analysis

Extracted kernel config via `/proc/config.gz`. Key findings:

**Enabled (Potential Attack Vectors):**
- `CONFIG_BPF=y` with `CONFIG_BPF_JIT=y`
- `CONFIG_KALLSYMS_ALL=y` (helps with KASLR bypass)
- `CONFIG_ANDROID_BINDER_IPC=y`
- `CONFIG_FTRACE=y`
- `CONFIG_ASHMEM=y`
- `CONFIG_FUSE_FS=y`

**Disabled/Hardened (Blocks Exploits):**
- `CONFIG_USERFAULTFD` - Not set
- `CONFIG_DEVMEM` - Not set
- `CONFIG_DEBUG_FS` - Not set
- `CONFIG_KPROBES` - Not set
- `CONFIG_HARDENED_USERCOPY=y`
- `CONFIG_FORTIFY_SOURCE=y`
- `CONFIG_STACKPROTECTOR_STRONG=y`
- `CONFIG_ARM64_PAN=y`
- `CONFIG_ARM64_UAO=y`

#### CVE Research

| CVE | Description | Applicable? |
|-----|-------------|-------------|
| CVE-2024-53197 | USB Audio privilege escalation | Maybe - requires USB device attack |
| CVE-2024-53104 | USB Video Class exploit | Maybe - POC exists |
| CVE-2023-20938 | Binder UAF | NO - affects kernel 5.4/5.10 only |
| CVE-2019-2215 | Binder UAF | NO - patched in 4.14+ |
| CVE-2024-1086 | Netfilter | NO - affects kernel 5.14-6.6 |

**Challenge:** Security patch level is 2025-04-05 (very recent), meaning most known CVEs are patched.

### STEP 3a: Recovery/Sideload Mode Testing (COMPLETED)

Successfully entered sideload mode:
```bash
adb reboot sideload  # Works!
```

**Findings:**
- Device shows as `sideload` mode in ADB
- Shell access is disabled in sideload mode (`error: closed`)
- Only accepts `adb sideload <file.zip>` commands
- **POTENTIAL VECTOR:** Could craft malicious OTA if we understand the signing requirements

**Output:**
```
List of devices attached
1017170                sideload product:icx1301_002 model:NW_A300Series device:icx1301
```

### STEP 3b: USB Exploit Research (PENDING)

CVE-2024-53104 and CVE-2024-53197 are USB-based attacks that could work:
- Requires crafting malicious USB device descriptors
- Part of Cellebrite exploit chain
- May still work if not patched

### STEP 3c: DSU (Dynamic System Update) Testing (NEW DISCOVERY!)

**MAJOR FINDING:** Device has DSU (Dynamic System Update) support!

```bash
# GSI tool exists and is functional
adb shell gsi_tool status  # Returns: "normal"

# DSU installer can be launched
adb shell am start -a android.os.image.action.START_INSTALL  # Works!
```

**DSU Service Details:**
- Package: `com.android.dynsystem`
- Has `INSTALL_DYNAMIC_SYSTEM` permission
- Has `MANAGE_DYNAMIC_SYSTEM` permission
- Has `READ_OEM_UNLOCK_STATE` permission
- Runs as system UID (1000)

**The Challenge:**
- DSU requires signed GSI images to boot on locked bootloader
- Need Google-signed GSI or OEM developer keys in ramdisk
- AVB version 1.1 in use

**Potential Vector:**
- If device includes Google's developer GSI AVB keys, could boot a signed GSI
- From GSI, could potentially dump boot partition and gain root
- Need to test if Google's official GSI will boot

### STEP 3d: Firmware Update Interception (IN PROGRESS)

#### System Updater Analysis

Found Sony's system updater: `com.sony.walkman.systemupdater` (automagic.apk)

**Key Findings from APK Analysis:**
- Uses `AES/CBC/PKCS5Padding` encryption
- Class: `UpdateDataDecipher`
- Update server: `https://info.update.sony.net/PA001/`
- Updates distributed as `.UPG` files (Sony proprietary encrypted format)
- Encryption key stored on device itself

**Problem:** Updates are encrypted with device-specific keys, cannot be intercepted and modified without root access first.

---

## Partition Map

Full partition layout discovered (84 partitions):

```
Key Partitions:
boot_a     -> /dev/block/mmcblk0p11
boot_b     -> /dev/block/mmcblk0p12   (current)
recovery_a -> /dev/block/mmcblk0p16
recovery_b -> /dev/block/mmcblk0p17
dtbo_a     -> /dev/block/mmcblk0p34
dtbo_b     -> /dev/block/mmcblk0p35
vbmeta_a   -> /dev/block/mmcblk0p62
vbmeta_b   -> /dev/block/mmcblk0p63
super      -> /dev/block/mmcblk0p13   (system/vendor/product)
userdata   -> /dev/block/mmcblk0p84

Boot Chain:
xbl_a/b     -> /dev/block/mmcblk0p1/2   (Primary bootloader)
tz_a/b      -> /dev/block/mmcblk0p5/6   (TrustZone)
hyp_a/b     -> /dev/block/mmcblk0p9/10  (Hypervisor)
abl_a/b     -> /dev/block/mmcblk0p28/29 (Android bootloader)
```

---

## Files Extracted

| File | Location | Purpose |
|------|----------|---------|
| kernel_config.txt | C:\tmp\kernel_config.txt | Kernel configuration |
| automagic.apk | C:\tmp\automagic.apk | System updater APK |

---

## Current Blockers

1. **Bootloader Lock**
   - Sony removed `fastboot oem unlock` command
   - No official Sony unlock service for Walkmans
   - OEM unlock allowed but no mechanism to use it

2. **EDL Mode Inaccessible**
   - ADB command rejected
   - No known hardware test points
   - Would need signed programmer anyway

3. **No Stock Boot Image**
   - No firmware packages available for download
   - Updates encrypted in .UPG format
   - Can't patch Magisk without boot.img

4. **Recent Security Patches**
   - 2025-04-05 patch level
   - Most kernel CVEs are patched

---

## Next Steps to Try

1. **Hardware EDL Access**
   - Research test points for QCS2290
   - Try USB-C EDL cable if obtainable

2. **USB-Based Exploits**
   - Build CVE-2024-53104 exploit device
   - Research CVE-2024-53197 chain

3. **Firmware Downgrade Attack**
   - Check if older firmware with known vulnerabilities exists
   - May require downgrade via recovery

4. **Recovery Mode Analysis**
   - Investigate what commands recovery accepts
   - Check for sideload vulnerabilities

5. **DIAG Mode Exploitation**
   - `/dev/diag` exists (Qualcomm diagnostic)
   - May allow low-level access if enabled

---

## Related Resources

- [XDA Forums - NW-A306 Root Discussion](https://xdaforums.com/t/q-root-newbie-sony-walkman-nw-a306-icx1301-root-without-boot-img-or-custom-recovery.4653262/)
- [GitHub - 2019 Android Walkman Research](https://github.com/97lily/2019_android_walkman/)
- [bkerler/edl - Qualcomm EDL Tool](https://github.com/bkerler/edl)
- [Aleph Security - EDL Exploitation](https://alephsecurity.com/vulns/aleph-2017028)
- [Android Kernel Exploitation Guide](https://cloudfuzz.github.io/android-kernel-exploitation/)

---

## Commands Reference

```bash
# ADB Connection
adb devices -l
adb shell getprop ro.product.device  # icx1301

# Fastboot Mode
adb reboot bootloader
fastboot getvar all

# Check Security Status
adb shell getprop ro.boot.flash.locked         # 1 (locked)
adb shell getprop ro.boot.verifiedbootstate    # green
adb shell getprop sys.oem_unlock_allowed       # 1

# Partition Access (requires root)
dd if=/dev/block/mmcblk0p12 of=/sdcard/boot_b.img  # Permission denied

# USB Config
adb shell getprop sys.usb.config  # mtp,adb
```

---

## Summary of Attack Vectors Tried

| Vector | Status | Result |
|--------|--------|--------|
| Fastboot OEM Unlock | BLOCKED | Sony removed command |
| EDL Mode | BLOCKED | Cannot enter via ADB, no test points |
| Kernel CVEs | BLOCKED | 2025-04-05 patches, most CVEs fixed |
| Recovery Sideload | AVAILABLE | Can sideload, but needs signed OTA |
| DSU/GSI | AVAILABLE | Service exists, but needs unlocked bootloader for unsigned GSI |
| DIAG Mode | LIMITED | Device exists but restricted |
| Firmware Downgrade | UNKNOWN | Updates encrypted in .UPG format |

## Current Best Paths Forward

1. **Hardware EDL Access** - Need to find test points or use USB-C EDL cable
2. **USB Exploits (CVE-2024-53104/53197)** - Requires building malicious USB device
3. **Signed GSI via DSU** - Would work if Google GSI keys are present
4. **Wait for Community** - Someone may find a bootloader unlock method

---

*Document will be updated as progress continues.*
