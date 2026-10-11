"""Generate a synthetic demo asset inventory (no real network scanning)."""
from __future__ import annotations

from app.db.models import Asset, AssetSoftware
from app.db.session import SessionLocal

DEMOS = [
    {
        "hostname": "web-dmz-01", "asset_type": "server", "criticality": 5, "exposure": "external",
        "network_zone": "dmz", "owner": "platform",
        "software": [("nginx", "nginx", "1.18.0"), ("openssl", "openssl", "1.1.1k"), ("linux", "linux_kernel", "5.4.0")],
    },
    {
        "hostname": "db-core-01", "asset_type": "server", "criticality": 5, "exposure": "internal",
        "network_zone": "core", "owner": "dba",
        "software": [("postgresql", "postgresql", "13.4"), ("linux", "linux_kernel", "5.4.0")],
    },
    {
        "hostname": "analytics-ws-01", "asset_type": "workstation", "criticality": 3, "exposure": "internal",
        "network_zone": "corp", "owner": "research",
        "software": [("google", "chrome", "96.0.4664.45"), ("microsoft", "windows_10", "1607")],
    },
    {
        "hostname": "vpn-edge-01", "asset_type": "network", "criticality": 4, "exposure": "dmz",
        "network_zone": "edge", "owner": "netops",
        "software": [("pulsesecure", "pulse_connect_secure", "9.0R")],
    },
    {
        "hostname": "build-cd-01", "asset_type": "server", "criticality": 2, "exposure": "internal",
        "network_zone": "corp", "owner": "devops",
        "software": [("jenkins", "jenkins", "2.277"), ("apache", "httpserver", "2.4.48")],
    },
]

UNVERIFIED_VERSIONS = {"vpn-edge-01"}  # partial CMDB coverage -> ambiguous matches


def seed() -> int:
    db = SessionLocal()
    if db.query(Asset).first() is not None:
        db.query(AssetSoftware).delete()
        db.query(Asset).delete()
        db.commit()
    for item in DEMOS:
        sw = item.pop("software")
        ambiguous = item["hostname"] in UNVERIFIED_VERSIONS
        asset = Asset(**item)
        db.add(asset)
        db.flush()
        for vendor, product, version in sw:
            asset.software.append(
                AssetSoftware(
                    vendor=vendor,
                    product=product,
                    version=None if ambiguous else version,
                    match_confidence="ambiguous" if ambiguous else "likely",
                )
            )
        db.commit()
    db.close()
    return len(DEMOS)


if __name__ == "__main__":
    n = seed()
    print(f"Seeded {n} demo assets with software inventory.")
