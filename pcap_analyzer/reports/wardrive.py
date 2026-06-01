# ================================================================
#  reports/wardrive.py
#  Wardriving table builder.
#  Produces both the formatted text table and the CSV DataFrame
#  from a shared set of AP entry dicts — no duplicated logic.
# ================================================================

import pandas as pd
from ..oui import lookup_vendor
from ..mac_utils import is_randomized_mac


def build_ap_entries(result, oui_db):
    """
    Build a list of AP summary dicts from the processed capture data.
    This is the shared core used by both the text table and the CSV export.

    Each dict contains: ssid, bssid, channel, band, rssi, clients, vendor, notes.
    The list is sorted by strongest RSSI descending.
    """
    df = result.df
    entries = []

    for ap_mac, info in result.ap_client_map.items():
        ssid = info.get("SSID", "<unknown>")
        clients = info.get("Clients", set())
        client_count = len(clients)

        ap_df = df[df["BSSID"] == ap_mac]
        if not ap_df.empty:
            channel_series = ap_df["Channel"].dropna()
            channel = int(channel_series.mode().iloc[0]) if not channel_series.empty else None

            band_series = ap_df["Band"].dropna()
            band = band_series.mode().iloc[0] if not band_series.empty else "Unknown"

            rssi_series = ap_df["RSSI"].dropna()
            strongest_rssi = int(rssi_series.max()) if not rssi_series.empty else None
        else:
            channel = None
            band = "Unknown"
            strongest_rssi = None

        vendor = lookup_vendor(ap_mac, oui_db)
        notes = _build_notes(ssid, strongest_rssi, client_count, clients, result.ssid_to_bssids)

        entries.append({
            "ssid":    ssid,
            "bssid":   ap_mac,
            "channel": channel,
            "band":    band,
            "rssi":    strongest_rssi,
            "clients": client_count,
            "vendor":  vendor,
            "notes":   ", ".join(notes) if notes else "",
        })

    # Sort by strongest RSSI descending (Nones last)
    entries.sort(key=lambda x: (x["rssi"] is not None, x["rssi"]), reverse=True)
    return entries


def build_wardriving_table(result, oui_db):
    """
    Build the formatted plain-text wardriving table.
    Returns a list of strings (one per line).
    """
    entries = build_ap_entries(result, oui_db)

    lines = ["=== Wardriving Summary ===\n"]

    header = (
        f"{'SSID':<18} {'BSSID':<18} {'CH':<4} {'BAND':<6} "
        f"{'RSSI':<6} {'CLIENTS':<8} {'VENDOR':<14} NOTES"
    )
    lines.append(header)
    lines.append("-" * len(header))

    for ap in entries:
        ssid_str    = ap["ssid"]    if ap["ssid"]    not in [None, ""] else "<unknown>"
        bssid_str   = ap["bssid"]   if ap["bssid"]   is not None       else "-"
        channel_str = str(ap["channel"]) if ap["channel"] is not None  else "-"
        band_str    = ap["band"]    if ap["band"]    is not None        else "Unknown"
        rssi_str    = str(ap["rssi"]) if ap["rssi"]  is not None        else "-"
        vendor_str  = ap["vendor"]  if ap["vendor"]  is not None        else "Unknown"

        lines.append(
            f"{ssid_str:<18} {bssid_str:<18} "
            f"{channel_str:<4} {band_str:<6} "
            f"{rssi_str:<6} {ap['clients']:<8} "
            f"{vendor_str:<14} {ap['notes']}"
        )

    return lines


def build_wardrive_csv(result, oui_db):
    """
    Build a pandas DataFrame for the wardrive CSV export.
    Uses the same AP entries as the text table — no duplicated logic.
    """
    entries = build_ap_entries(result, oui_db)

    rows = []
    for ap in entries:
        rows.append({
            "SSID":    ap["ssid"],
            "BSSID":   ap["bssid"],
            "Channel": ap["channel"],
            "Band":    ap["band"],
            "RSSI":    ap["rssi"],
            "Clients": ap["clients"],
            "Vendor":  ap["vendor"],
            "Notes":   ap["notes"],
        })

    return pd.DataFrame(rows)


# ----------------------------------------------------------------
# Private helpers
# ----------------------------------------------------------------

def _build_notes(ssid, strongest_rssi, client_count, clients, ssid_to_bssids):
    """Build the list of note strings for a single AP entry."""
    notes = []

    if ssid == "<hidden>":
        notes.append("Hidden SSID")

    if strongest_rssi is not None:
        if strongest_rssi >= -50:
            notes.append("Strong signal")
        elif strongest_rssi <= -80:
            notes.append("Weak signal")

    if client_count >= 10:
        notes.append("Busy AP")
    elif client_count == 0:
        notes.append("No clients")

    if any(is_randomized_mac(c) for c in clients):
        notes.append("Randomized clients")

    if ssid and ssid != "<hidden>":
        if ssid in ssid_to_bssids and len(ssid_to_bssids[ssid]) > 1:
            notes.append("Multi-BSSID")

    return notes
