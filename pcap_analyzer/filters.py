# ================================================================
#  filters.py
#  Packet filtering and CSV export selection helpers
# ================================================================

from scapy.all import Dot11


def packet_passes_filters(pkt, filters):
    """
    Check whether a packet matches all user-supplied --filter arguments.

    Parameters
    ----------
    pkt     : scapy packet
    filters : list of 'key=value' strings from args.filter, or None

    Returns True if the packet should be processed, False if it should be skipped.
    """
    # No filters supplied → everything passes
    if not filters:
        return True

    # Only Dot11 frames are filterable
    if not pkt.haslayer(Dot11):
        return False

    dot11 = pkt[Dot11]

    for flt in filters:
        if "=" not in flt:
            continue

        key, value = flt.split("=", 1)
        key = key.strip().lower()
        value = value.strip()

        if key == "ssid":
            ssid = None
            if hasattr(pkt, "info"):
                try:
                    ssid = pkt.info.decode(errors="ignore")
                except Exception:
                    ssid = None
            if not ssid or ssid != value:
                return False

        elif key == "mac":
            macs = [
                str(dot11.addr1).lower() if dot11.addr1 else "",
                str(dot11.addr2).lower() if dot11.addr2 else "",
                str(dot11.addr3).lower() if dot11.addr3 else "",
            ]
            if value.lower() not in macs:
                return False

        elif key == "type":
            try:
                if dot11.type != int(value):
                    return False
            except ValueError:
                return False

        elif key == "subtype":
            try:
                if dot11.subtype != int(value):
                    return False
            except ValueError:
                return False

        # Unknown filter keys are silently ignored

    return True


def should_export(name, requested_csvs):
    """
    Determine whether a given CSV export should be written.

    Parameters
    ----------
    name          : CSV name string (e.g. 'frames', 'clients')
    requested_csvs: set of names the user requested, or None for 'export all'

    Returns True if this CSV should be written.
    """
    if requested_csvs is None:
        return True
    return name.lower() in requested_csvs
