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
4. **CVE-2024-43047 DSP Exploit** - No public POC, likely patched (2025-04-05)
5. **Wait for Community** - Someone may find a bootloader unlock method

## CVE Research Summary

| CVE | Type | Status | Notes |
|-----|------|--------|-------|
| CVE-2024-43047 | Qualcomm DSP UAF | Likely Patched | No public POC, spyware-only |
| CVE-2024-53104 | USB Video Class | **NOT VULNERABLE** | CONFIG_USB_VIDEO not compiled |
| CVE-2024-53197 | USB Audio | **LIKELY VULNERABLE** | CONFIG_SND_USB_AUDIO=y, kernel 4.19.157 < 4.19.325 |
| CVE-2024-50302 | HID Multitouch | Unknown | Part of Cellebrite chain |
| CVE-2023-20938 | Binder UAF | N/A | Only affects kernel 5.4/5.10 |
| CVE-2019-2215 | Binder UAF | N/A | Patched in kernel 4.14+ |

---

## USB Exploit Research (Cellebrite Chain Analysis)

### Overview

Cellebrite developed a USB-based exploit chain used to unlock Android devices. The chain uses emulated USB devices to trigger kernel vulnerabilities and achieve root access.

### Kernel Configuration Check

```
# UVC (Video) - NOT VULNERABLE
CONFIG_USB_CONFIGFS_F_UVC is not set

# USB Audio - VULNERABLE!
CONFIG_SND_USB_AUDIO=y
CONFIG_SND_USB_ICX=y  # Sony-specific!
```

The Walkman kernel (4.19.157) is older than the patched version (4.19.325) for CVE-2024-53197.

### Cellebrite USB Device Chain

| Device | VID:PID | CVE | Purpose |
|--------|---------|-----|---------|
| UVC Webcam | 04f2:b071 | CVE-2024-53104 | Memory corruption (NOT applicable) |
| Extigy Sound Card | 041e:3000 | CVE-2024-53197 | Descriptor corruption |
| FastTrackPro | 0763:2012 | CVE-2024-53197 | Follow-up exploitation |
| Anton Touchpad | 1130:3101 | CVE-2024-50302 | Kernel memory leak |
| Microsoft Mouse | 045e:076c | - | Final exploitation |

### Attack Sequence

1. **Memory grooming** (0-40s): HID Mouse connections
2. **Memory corruption** (40-121s): USB Audio device descriptor manipulation
3. **Code execution** (121-246s): Final HID connections → root shell

### Hardware Required

- **Facedancer** or **GreatFET** - USB device emulator ($50-150)
- **Raspberry Pi Zero** - Alternative for USB gadget mode (~$15)
- **Rooted Android Phone** - Free if you have one with ConfigFS support
- **USB-C OTG adapter** - To connect to Walkman

### Potential Attack Path for Walkman

Since CVE-2024-53104 (UVC) is not applicable (driver not compiled), we need to:

1. Focus on **CVE-2024-53197** (USB Audio) - driver IS present
2. Emulate Extigy (041e:3000) or FastTrackPro (0763:2012)
3. Manipulate `bNumConfigurations` to trigger OOB access
4. Chain with CVE-2024-50302 (HID) for memory leak + code exec

### Next Steps

1. Obtain Facedancer/GreatFET or configure Raspberry Pi Zero
2. Create USB Audio device emulator with malformed descriptors
3. Test against Walkman's kernel 4.19.157
4. If successful, dump boot partition and flash custom kernel

---

## Can a Standard PC Be Used as USB Attack Device?

### Short Answer: NO (for most PCs)

Standard desktop PCs only have USB **Host Controllers** (xHCI). To emulate a USB device, you need a **USB Device Controller (UDC)**.

### PC USB Attack Options Investigated

| Method | Result | Notes |
|--------|--------|-------|
| Intel xDCI | ❌ AMD system - not available | Only on Intel mobile platforms |
| Thunderbolt 4 Device Mode | ❌ JHL8540 is host-only | JHL8440 is device controller (for peripherals) |
| WSL2 + USB/IP | ❌ Cannot emulate devices | Only forwards host USB to VM |
| QEMU USB Emulation | ❌ Virtual only | Emulated devices connect to VM, not physical |
| Dummy HCD | ⚠️ Local testing only | Creates virtual USB host+device pair in kernel |
| Raw Gadget | ❌ Requires UDC hardware | Great tool but needs Pi Zero/similar |

### Which PCs CAN Do USB Device Mode?

1. **Intel laptops with xDCI** (hidden BIOS feature)
   - ThinkPad X1 Carbon (requires BIOS mod)
   - Some Intel NUCs
   - Intel-based tablets

2. **Devices with USB OTG/Dual-Role**
   - Raspberry Pi 4 (USB-C port only)
   - Raspberry Pi Zero/Zero W/Zero 2 W
   - BeagleBone Black
   - Many Android phones (with root)

### Rooted Android Phone as Attack Device

If you have a rooted Android phone with ConfigFS kernel support:

```bash
# Check if ConfigFS is available
adb shell "ls /config/usb_gadget/"

# With root, you can create custom USB gadgets:
# 1. Disable existing Android USB gadget
# 2. Create new gadget with Extigy VID:PID (0x041e:0x3000)
# 3. Configure UAC audio function
# 4. Connect to Walkman via OTG
```

**Tools:**
- [USB Gadget Tool](https://github.com/tejado/android-usb-gadget) - GUI for common gadgets
- Manual ConfigFS scripts for custom devices (audio not in GUI)

### Why Desktop PCs Can't Do This

Desktop motherboards (including ASUS ProArt X670E-CREATOR WIFI) use:
- AMD USB controllers - Host mode only
- Intel Thunderbolt (JHL8540) - Host controller, not device
- No USB OTG/Dual-Role ports

The USB specification defines two roles:
- **Host**: Controls bus, initiates transfers (your PC)
- **Device/Peripheral**: Responds to host (keyboard, Walkman, etc.)

Desktop PCs are designed to BE hosts, not to BE devices.

---

## Hardware Recommendations

### Budget Option: Raspberry Pi Zero W (~$15)
- Full USB device mode support
- WiFi for remote control from PC
- Runs Linux with ConfigFS
- Can emulate any USB device

### If You Have: Rooted Android Phone (FREE)
- Check for ConfigFS support: `ls /config/usb_gadget/`
- Need kernel with USB gadget drivers
- More complex setup than Pi Zero

### Professional: GreatFET One (~$100)
- Designed for USB security research
- Best documentation and support
- Works with Facedancer framework

---

## Kernel/Firmware Rollback Analysis

### Can We Downgrade to a More Vulnerable Kernel?

**Short Answer: NO - Multiple hardware protections prevent this.**

### Protection Layers

| Protection | Status | Impact |
|------------|--------|--------|
| **Bootloader Lock** | LOCKED | Cannot flash any unsigned images |
| **AVB (Android Verified Boot)** | Active (GREEN) | Verifies cryptographic signatures on every boot |
| **Anti-Rollback Index** | Stored in RPMB | Hardware counter prevents booting older images |
| **Sony OEM Lock** | Command removed | No `fastboot oem unlock` available |

### How Anti-Rollback Works

Android stores a **rollback index** in the device's RPMB (Replay Protected Memory Block) - a tamper-resistant secure storage area in the eMMC. Each firmware update increments this counter. The bootloader refuses to boot any image with a lower rollback index, even if properly signed.

```
Current device: rollback_index = N
Older firmware: rollback_index = N-X
Result: BOOT BLOCKED by hardware (even with valid signature)
```

### Theoretical Bypass (Requires Unlocked Bootloader)

According to XDA Forums research on bypassing rollback protection:

> "In theory, a bootloader in UNLOCKED state should ignore rollback protection... Since the bootloader is unlocked, it will still accept any signature key."

The method involves:
1. Extract old firmware partition images
2. Forge new VBMeta with current rollback index but old kernel
3. Sign with random key (unlocked bootloader accepts any key)
4. Flash the modified images

**BUT** - This requires an **UNLOCKED bootloader**, which Sony has completely blocked on the NW-A306.

### Firmware Availability

Sony only provides the latest firmware version for download:
- Official support pages only offer 3.02.01 / 3.03.01
- No official archive of older versions (2.x, 3.00, 3.01)
- .UPG files are encrypted and device-specific

Even if an older .UPG file was found:
1. The system updater checks rollback index
2. Device refuses to install older versions
3. Sony explicitly states: "The software cannot be downgraded to its previous version"

### MrWalkman Custom Firmware (Not Applicable)

MrWalkman creates custom firmware for older **non-Android** Walkmans:
- A30/A40/A50 Series (Linux-based, not Android)
- WM1A/WM1Z (Original, not M2 models)
- ZX300 Series

The NW-A306 runs **Android 14** with full Google security stack - completely different architecture. No custom firmware exists for Android-based Walkmans.

### Conclusion

**Kernel rollback is NOT a viable attack vector** because:
1. Bootloader is locked (cannot flash anything)
2. Anti-rollback counter in RPMB (hardware enforced)
3. No older firmware files publicly available
4. Would need root first to bypass checks (chicken-and-egg)

**The USB exploit (CVE-2024-53197) remains the best path** because it attacks the **running kernel** directly, bypassing all boot-time verification.

### References
- [XDA Forums - Bypassing Rollback Protection](https://xdaforums.com/t/advanced-bypassing-rollback-protection-to-downgrade-the-os.4511501/)
- [Sony UK - NW-A306 Downloads](https://www.sony.co.uk/electronics/support/digital-music-players-nw-nwz-a-series/nw-a306/downloads)
- [MrWalkman Custom Firmware](https://www.mrwalkman.com/p/a30series.html) (non-Android only)

---

*Document will be updated as progress continues.*
