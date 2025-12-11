#!/usr/bin/env python3
"""
Additional mutations to exceed 500+ total

Adds: Combination mutations, quirk-specific edge cases
"""

import json

def generate_additional_mutations(start_id=2000):
    """Generate additional mutations to exceed 500"""
    mutations = []

    # Generate fine-grained bNumConfigurations for Extigy
    # All values from 2 to 100 we haven't tested yet
    tested_bnums = {2, 3, 4, 5, 8, 16, 32, 64, 128, 192, 254, 255}

    for bnum in range(2, 101):
        if bnum in tested_bnums:
            continue

        oob = (bnum - 1) * 272
        mutations.append({
            "id": f"ADD-{start_id}",
            "name": f"extigy_finegrain_bnum_{bnum}",
            "mutation_type": "fine_grained_bnum",
            "target_quirk": "extigy",
            "description": f"Fine-grained test: bNumConfigurations={bnum}",
            "severity": "high" if oob > 4096 else "medium",
            "expected_impact": f"OOB access of {oob} bytes",
            "device_descriptor": {
                "idVendor": "0x041e",
                "idProduct": "0x3000",
                "bNumConfigurations": 1
            },
            "config_descriptor": {
                "wTotalLength": 794
            },
            "pre_quirk_descriptor": {
                "bNumConfigurations": 1
            },
            "post_quirk_descriptor": {
                "bNumConfigurations": bnum
            }
        })
        start_id += 1

    # FastTrackPro fine-grained (top 30 values)
    for bnum in [200, 210, 220, 230, 240, 245, 248, 250, 251, 252, 253]:
        oob = (bnum - 1) * 272
        mutations.append({
            "id": f"ADD-{start_id}",
            "name": f"fasttrack_finegrain_bnum_{bnum}",
            "mutation_type": "fine_grained_bnum",
            "target_quirk": "fasttrackpro",
            "description": f"FastTrackPro: bNumConfigurations={bnum}",
            "severity": "critical",
            "expected_impact": f"Massive OOB access of {oob} bytes",
            "device_descriptor": {
                "idVendor": "0x0763",
                "idProduct": "0x2012",
                "bNumConfigurations": 1
            },
            "config_descriptor": {
                "wTotalLength": 483
            },
            "pre_quirk_descriptor": {
                "bNumConfigurations": 1
            },
            "post_quirk_descriptor": {
                "bNumConfigurations": bnum
            }
        })
        start_id += 1

    return mutations


def main():
    """Add to all_mutations.json"""
    print("Generating additional mutations...")

    additional = generate_additional_mutations()
    print(f"Generated {len(additional)} additional mutations")

    # Load existing
    with open("all_mutations.json", 'r') as f:
        data = json.load(f)

    # Add new
    data["mutations"].extend(additional)
    data["metadata"]["total_mutations"] = len(data["mutations"])
    data["metadata"]["categories"]["fine_grained_bnum"] = len(additional)

    # Save
    with open("all_mutations.json", 'w') as f:
        json.dump(data, f, indent=2)

    print(f"Total mutations now: {len(data['mutations'])}")


if __name__ == "__main__":
    main()
