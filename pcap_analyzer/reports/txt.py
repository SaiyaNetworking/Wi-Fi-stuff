# ================================================================
#  reports/txt.py
#  Plain-text report builder.
#  Produces the summary and per-client session report lines.
# ================================================================

import os
from ..oui import lookup_vendor
from ..mac_utils import is_randomized_mac
from .wardrive import build_wardriving_table


def write_txt_report(result, anomalies, oui_db, args):
    """
    Write the full plain-text report to disk.

    Respects --wardrive (table only), --summary-only (no session reports),
    and full mode (everything).
    """
    txt_path = os.path.join(args.out, "wireless_summary.txt")
    print("Writing TXT summary...")

    with open(txt_path, "w") as f:
        # Wardriving table always appears first
        for line in build_wardriving_table(result, oui_db):
            f.write(line + "\n")

        if args.wardrive:
            # Wardrive mode: table only, nothing else
            pass

        elif args.summary_only:
            for line in _build_summary_lines(result, anomalies, oui_db):
                f.write(line + "\n")
            f.write("\n=== Light TXT Mode Enabled ===\n")
            f.write("Session reports and per-SSID raw tables were skipped.\n")

        else:
            for line in _build_summary_lines(result, anomalies, oui_db):
                f.write(line + "\n")
            for line in _build_session_lines(result, anomalies, oui_db):
                f.write(line + "\n")

            # Per-SSID raw frame tables
            grouped = result.df.groupby("SSID")
            for ssid, group in grouped:
                f.write(f"\n=== SSID: {ssid} ===\n")
                f.write(group.to_string(index=False))
                f.write("\n")

    print(f"    TXT output saved to {txt_path}")


# ----------------------------------------------------------------
# Summary section
# ----------------------------------------------------------------

def _build_summary_lines(result, anomalies, oui_db):
    """Build the main capture summary block."""
    lines = []
    df = result.df

    lines.append("=== Wireless Capture Summary ===")
    lines.append(f"Total Frames: {len(df)}")
    lines.append(f"Unique SSIDs: {df['SSID'].nunique()}")

    # Hidden SSIDs
    lines.append("\nHidden SSIDs Revealed:")
    if result.revealed_ssids:
        for ap_mac, ssid in sorted(result.revealed_ssids.items(), key=lambda x: x[1].lower()):
            lines.append(f"  {ap_mac} → {ssid}")
    else:
        lines.append("  None detected")

    # Randomized MACs
    lines.append("\nRandomized MAC Addresses:")
    if result.randomized_macs:
        for mac in sorted(result.randomized_macs):
            lines.append(f"  {mac}")
    else:
        lines.append("  None detected")

    # Randomized MAC → AP/SSID associations
    lines.append("\nRandomized MAC Associations:")
    if result.randomized_associations:
        for mac, targets in sorted(result.randomized_associations.items()):
            lines.append(f"  {mac}:")
            for ssid, bssid in sorted(targets, key=lambda x: (x[0] or "", x[1] or "")):
                lines.append(f"      SSID={ssid}, BSSID={bssid}")
    else:
        lines.append("  None detected")

    # AP–Client associations
    lines.append("\nAP–Client Associations:")
    if result.ap_client_map:
        for ap_mac, info in sorted(result.ap_client_map.items()):
            ssid = info["SSID"]
            clients = info["Clients"]
            ap_band = _mode_band(df, bssid=ap_mac)
            lines.append(f"  AP {ap_mac} (SSID={ssid}, Band={ap_band}):")
            for client in sorted(clients):
                vendor = lookup_vendor(client, oui_db)
                lines.append(f"      {client} ({vendor})")
    else:
        lines.append("  None detected")

    # Roaming events
    lines.append("\nRoaming Events:")
    if result.roaming_events:
        for client, events in sorted(result.roaming_events.items()):
            lines.append(f"  Client {client}:")
            for old_ap, new_ap, ssid, ts in sorted(events, key=lambda x: x[3]):
                new_band = _mode_band(df, bssid=new_ap)
                lines.append(
                    f"      {ts:.2f} — {old_ap} → {new_ap} (SSID={ssid}, Band={new_band})"
                )
    else:
        lines.append("  None detected")

    # Client timelines
    lines.append("\nClient Timelines:")
    for client in sorted(result.client_first_seen.keys()):
        first = result.client_first_seen[client]
        last  = result.client_last_seen[client]
        duration = last - first
        client_band = _mode_band(df, source=client)
        lines.append(
            f"  {client}: first={first:.2f}, last={last:.2f}, "
            f"duration={duration:.2f}s, Band={client_band}"
        )

    # SSID activity windows
    lines.append("\nSSID Activity Windows:")
    for ssid, times in sorted(result.ssid_activity.items()):
        first = min(times)
        last  = max(times)
        ssid_band = _mode_band(df, ssid=ssid)
        lines.append(
            f"  {ssid}: {first:.2f} → {last:.2f} ({len(times)} frames, Band={ssid_band})"
        )

    # AP load over time
    lines.append("\nAP Load Over Time:")
    if result.ap_load_timeline:
        for ap, entries in sorted(result.ap_load_timeline.items()):
            ssid = result.ap_client_map.get(ap, {}).get("SSID", "Unknown")
            ap_band = _mode_band(df, bssid=ap)
            lines.append(f"  AP {ap} (SSID={ssid}, Band={ap_band}):")
            for ts, count in entries:
                lines.append(f"      {ts:.2f} — {count} clients")
    else:
        lines.append("  None tracked")

    # RSSI summary
    lines.append("\nRSSI Summary:")
    if result.client_rssi:
        for client, samples in sorted(result.client_rssi.items()):
            values = [v for (_, v) in samples if v is not None]
            client_band = _mode_band(df, source=client)
            if values:
                lines.append(
                    f"  {client}: strongest={max(values)} dBm, "
                    f"weakest={min(values)} dBm, "
                    f"avg={sum(values)/len(values):.1f} dBm, Band={client_band}"
                )
            else:
                lines.append(f"  {client}: No RSSI data available, Band={client_band}")
    else:
        lines.append("  No RSSI data collected")

    # Observed bands
    lines.append("\nObserved Frequency Bands:")
    lines.append(f"  2.4 GHz: {'Yes' if result.observed_bands['2.4GHz'] else 'No'}")
    lines.append(f"  5 GHz:   {'Yes' if result.observed_bands['5GHz'] else 'No'}")
    lines.append(f"  6 GHz:   {'Yes' if result.observed_bands['6GHz'] else 'No'}")

    # Anomalies
    lines.append("\nAnomalies Detected:")
    if anomalies:
        for a in anomalies:
            lines.append(f"  - {a}")
    else:
        lines.append("  None detected")

    # Frames per SSID
    lines.append("\nFrames Per SSID:")
    ssid_counts = df.groupby("SSID").size().reset_index(name="Frames")
    for _, row in ssid_counts.iterrows():
        lines.append(f"  {row['SSID']}: {row['Frames']}")

    lines.append("\n================================\n")
    return lines


# ----------------------------------------------------------------
# Per-client session report section
# ----------------------------------------------------------------

def _build_session_lines(result, anomalies, oui_db):
    """Build the per-client session report block."""
    lines = ["=== Client Session Reports ==="]
    df = result.df

    for client in sorted(result.client_first_seen.keys()):
        vendor       = lookup_vendor(client, oui_db)
        first        = result.client_first_seen.get(client)
        last         = result.client_last_seen.get(client)
        duration     = (last - first) if (first is not None and last is not None) else None
        is_randomized = client in result.randomized_macs
        client_band  = _mode_band(df, source=client)

        lines.append(f"\n=== Client: {client} ({vendor}, Band={client_band}) ===")
        if first    is not None: lines.append(f"First Seen: {first:.2f}")
        if last     is not None: lines.append(f"Last Seen:  {last:.2f}")
        if duration is not None: lines.append(f"Duration:   {duration:.2f}s")
        lines.append(f"Randomized MAC: {'Yes' if is_randomized else 'No'}")

        # Probe activity
        lines.append("\nProbe Activity:")
        client_probes = df[(df["Type"] == 0) & (df["Subtype"] == 4) & (df["Source"] == client)]
        if not client_probes.empty:
            for _, row in client_probes.sort_values("Timestamp").iterrows():
                lines.append(
                    f"  {row['Timestamp']:.2f} — Probed for \"{row['SSID']}\" "
                    f"(Band={row.get('Band', 'Unknown')})"
                )
        else:
            lines.append("  None observed")

        # Associations
        lines.append("\nAssociations:")
        assoc_frames = df[
            (df["Type"] == 0) &
            (df["Subtype"].isin([0, 2])) &
            (df["Source"] == client)
        ]
        if not assoc_frames.empty:
            for _, row in assoc_frames.sort_values("Timestamp").iterrows():
                lines.append(
                    f"  {row['Timestamp']:.2f} — Associated to AP {row['BSSID']} "
                    f"(SSID={row['SSID']}, Band={row.get('Band', 'Unknown')})"
                )
        else:
            lines.append("  None observed")

        # Roaming
        lines.append("\nRoaming:")
        if client in result.roaming_events:
            for old_ap, new_ap, ssid, ts in sorted(result.roaming_events[client], key=lambda x: x[3]):
                new_band = _mode_band(df, bssid=new_ap)
                lines.append(
                    f"  {ts:.2f} — {old_ap} → {new_ap} (SSID={ssid}, Band={new_band})"
                )
        else:
            lines.append("  None observed")

        # RSSI stats
        lines.append("\nRSSI Stats:")
        samples = result.client_rssi.get(client, [])
        values = [v for (_, v) in samples if v is not None]
        if values:
            lines.append(
                f"  Strongest: {max(values)} dBm, "
                f"Weakest: {min(values)} dBm, "
                f"Avg: {sum(values)/len(values):.1f} dBm"
            )
        else:
            lines.append("  No RSSI data available")

        # Client-specific anomalies
        lines.append("\nAnomalies:")
        client_anoms = [a for a in anomalies if client in a]
        if client_anoms:
            for a in client_anoms:
                band = _mode_band(df, source=client)
                lines.append(f"  - {a} (Band={band})")
        else:
            lines.append("  None recorded")

    lines.append("\n================================\n")
    return lines


# ----------------------------------------------------------------
# Shared helper
# ----------------------------------------------------------------

def _mode_band(df, bssid=None, source=None, ssid=None):
    """
    Return the most common Band value for a given BSSID, Source MAC, or SSID.
    Returns 'Unknown' if no data is available.
    """
    if bssid:
        series = df[df["BSSID"] == bssid]["Band"]
    elif source:
        series = df[df["Source"] == source]["Band"]
    elif ssid:
        series = df[df["SSID"] == ssid]["Band"]
    else:
        return "Unknown"

    mode = series.mode()
    return mode.iloc[0] if not mode.empty else "Unknown"
