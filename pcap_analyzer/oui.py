# ================================================================
#  oui.py
#  OUI database loading and vendor lookup
# ================================================================

def load_oui_database(path="oui.txt"):
    """
    Load the OUI MAC vendor database from a text file.
    Returns a dict mapping 'AA:BB:CC' prefix → vendor name string.
    """
    oui_map = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" in line:
                parts = line.split("(hex)")
                prefix = parts[0].strip().replace("-", ":")
                vendor = parts[1].strip()
                oui_map[prefix] = vendor
    return oui_map


def lookup_vendor(mac, oui_map):
    """
    Look up a MAC address in the OUI database.
    Returns the vendor name string, or 'Unknown Vendor' if not found.
    """
    if mac is None:
        return "Unknown Vendor"
    prefix = mac.upper()[0:8]
    return oui_map.get(prefix, "Unknown Vendor")
