# ================================================================
#  mac_utils.py
#  MAC address utility functions
# ================================================================

def is_randomized_mac(mac):
    """
    Detect whether a MAC address is locally administered (randomized).
    The second-least-significant bit of the first byte indicates this.
    Returns True if randomized, False otherwise.
    """
    if mac is None:
        return False
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0b00000010)
    except Exception:
        return False
