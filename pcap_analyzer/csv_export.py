# ================================================================
#  reports/csv_export.py
#  CSV export logic.
#  Builds DataFrames from the PcapResult and writes them to disk.
# ================================================================

import os
import pandas as pd

from ..oui import lookup_vendor
from ..mac_utils import is_randomized_mac
from ..filters import should_export
from .wardrive import build_wardrive_csv


def export_all_csvs(result, anomalies, oui_db, args):
    """
    Build and write all requested CSV files to args.out.

    Respects --csv-list (via args.requested_csvs) and --no-csv.
    """
    print("    Building CSV data structures. This may take a while...")

    req = args.requested_csvs  # set of names, or None for "all"

    if should_export("frames", req):
        _write(result.df, "frames.csv", args.out)

    if should_export("clients", req):
        _write(_build_clients_df(result, anomalies, oui_db), "clients.csv", args.out)

    if should_export("aps", req):
        _write(_build_aps_df(result, oui_db), "aps.csv", args.out)

    if should_export("anomalies", req):
        _write(pd.DataFrame([{"Description": a} for a in anomalies]), "anomalies.csv", args.out)

    if should_export("roaming", req):
        _write(_build_roaming_df(result), "roaming.csv", args.out)

    if should_export("rssi_timeline", req):
        _write(_build_rssi_df(result), "rssi_timeline.csv", args.out)

    if should_export("ssid_activity", req):
        _write(_build_ssid_activity_df(result), "ssid_activity.csv", args.out)

    if should_export("ap_load_timeline", req):
        _write(_build_ap_load_df(result), "ap_load_timeline.csv", args.out)

    if should_export("randomized_associations", req):
        _write(_build_rand_assoc_df(result), "randomized_associations.csv", args.out)

    if should_export("wardrive", req):
        _write(build_wardrive_csv(result, oui_db), "wardrive.csv", args.out)

    if should_export("frequencies", req):
        freq_df = result.df[["Timestamp", "Source", "BSSID", "Channel", "FrequencyMHz", "Band"]]
        _write(freq_df, "frequencies.csv", args.out)

    if should_export("auth_failures", req):
        _write(_build_auth_failures_df(result), "auth_failures.csv", args.out)

    if should_export("assoc_failures", req):
        _write(_build_assoc_failures_df(result), "assoc_failures.csv", args.out)

    if should_export("deauth_events", req):
        _write(_build_deauth_events_df(result), "deauth_events.csv", args.out)

    if should_export("disassoc_events", req):
        _write(_build_disassoc_events_df(result), "disassoc_events.csv", args.out)

    if should_export("client_event_timeline", req):
        _write(_build_client_event_timeline_df(result), "client_event_timeline.csv", args.out)

    if should_export("dhcp_events", req):
        _write(pd.DataFrame(result.dhcp_events), "dhcp_events.csv", args.out)

    if should_export("dhcp_sessions", req):
        _write(_build_dhcp_sessions_df(result), "dhcp_sessions.csv", args.out)

    print("    CSV exports complete.")


# ----------------------------------------------------------------
# DataFrame builders
# ----------------------------------------------------------------

def _build_clients_df(result, anomalies, oui_db):
    """Per-client summary: timing, RSSI, activity counts."""
    print("    Building Per-Client Summary CSV...")
    rows = []

    for client in sorted(result.client_first_seen.keys()):
        first    = result.client_first_seen.get(client)
        last     = result.client_last_seen.get(client)
        duration = (last - first) if (first is not None and last is not None) else None
        vendor   = lookup_vendor(client, oui_db)
        is_rand  = client in result.randomized_macs

        samples = result.client_rssi.get(client, [])
        rssi_values = [v for (_, v) in samples if v is not None]

        client_band = _mode_band(result.df, source=client)

        probe_count = len(result.probe_times.get(client, []))
        assoc_count = len(
            result.df[(result.df["Type"] == 0) &
                       (result.df["Subtype"].isin([0, 2])) &
                       (result.df["Source"] == client)]
        )
        roam_count    = len(result.roaming_events.get(client, []))
        anomaly_count = sum(1 for a in anomalies if client in a)

        rows.append({
            "ClientMAC":       client,
            "Vendor":          vendor,
            "FirstSeen":       first,
            "LastSeen":        last,
            "DurationSeconds": duration,
            "RandomizedMAC":   is_rand,
            "ProbeCount":      probe_count,
            "AssociationCount": assoc_count,
            "RoamCount":       roam_count,
            "AnomalyCount":    anomaly_count,
            "RSSI_Strongest":  max(rssi_values) if rssi_values else None,
            "RSSI_Weakest":    min(rssi_values) if rssi_values else None,
            "RSSI_Average":    (sum(rssi_values) / len(rssi_values)) if rssi_values else None,
            "DominantBand":    client_band,
        })

    return pd.DataFrame(rows)


def _build_aps_df(result, oui_db):
    """AP summary: SSID, vendor, client count, dominant band."""
    print("    Building AP Summary CSV...")
    rows = []
    for ap, info in result.ap_client_map.items():
        ap_band = _mode_band(result.df, bssid=ap)
        rows.append({
            "AP_BSSID":    ap,
            "SSID":        info["SSID"],
            "Vendor":      lookup_vendor(ap, oui_db),
            "ClientCount": len(info["Clients"]),
            "DominantBand": ap_band,
        })
    return pd.DataFrame(rows)


def _build_roaming_df(result):
    """Roaming events: client, old AP, new AP, SSID, timestamp, band."""
    print("    Building Roaming Events CSV...")
    rows = []
    for client, events in result.roaming_events.items():
        for old_ap, new_ap, ssid, ts in events:
            new_band = _mode_band(result.df, bssid=new_ap)
            rows.append({
                "ClientMAC": client,
                "OldAP":     old_ap,
                "NewAP":     new_ap,
                "SSID":      ssid,
                "Timestamp": ts,
                "Band":      new_band,
            })
    return pd.DataFrame(rows)


def _build_rssi_df(result):
    """RSSI timeline: one row per (client, timestamp) sample."""
    print("    Building RSSI Timeline CSV...")
    rows = []
    for client, samples in result.client_rssi.items():
        for ts, rssi in samples:
            rows.append({
                "ClientMAC": client,
                "Timestamp": float(ts),
                "RSSI":      rssi,
            })

    if not rows:
        return pd.DataFrame(columns=["ClientMAC", "Timestamp", "RSSI", "Band"])

    rssi_df = pd.DataFrame(rows)

    # Merge band info from the main DataFrame
    band_df = result.df[["Source", "Timestamp", "Band"]].copy()
    band_df["Timestamp"] = band_df["Timestamp"].astype(float)
    band_df = band_df.rename(columns={"Source": "ClientMAC"})

    rssi_df = rssi_df.merge(band_df, on=["ClientMAC", "Timestamp"], how="left")
    rssi_df["Band"] = rssi_df["Band"].fillna("Unknown")
    return rssi_df


def _build_ssid_activity_df(result):
    """SSID activity windows: first/last seen, frame count, dominant band."""
    print("    Building SSID Activity CSV...")
    rows = []
    for ssid, times in result.ssid_activity.items():
        if not times:
            continue
        ssid_band = _mode_band(result.df, ssid=ssid)
        rows.append({
            "SSID":         ssid,
            "FirstSeen":    min(times),
            "LastSeen":     max(times),
            "FrameCount":   len(times),
            "DominantBand": ssid_band,
        })
    return pd.DataFrame(rows)


def _build_ap_load_df(result):
    """AP load timeline: one row per (AP, timestamp) with client count."""
    print("    Building AP Load Timeline CSV...")
    rows = []
    for ap, entries in result.ap_load_timeline.items():
        ap_band = _mode_band(result.df, bssid=ap)
        for ts, count in entries:
            rows.append({
                "AP_BSSID":    ap,
                "Timestamp":   ts,
                "ClientCount": count,
                "Band":        ap_band,
            })
    return pd.DataFrame(rows)


def _build_rand_assoc_df(result):
    """Randomized MAC associations: MAC, SSID, BSSID, band."""
    print("    Building Randomized MAC Associations CSV...")
    rows = []
    for mac, targets in result.randomized_associations.items():
        for ssid, bssid in targets:
            band_series = result.df[(result.df["Source"] == mac) & (result.df["BSSID"] == bssid)]["Band"]
            band = band_series.iloc[0] if not band_series.empty else "Unknown"
            rows.append({
                "RandomizedMAC": mac,
                "SSID":          ssid,
                "BSSID":         bssid,
                "Band":          band,
            })
    return pd.DataFrame(rows)


def _build_auth_failures_df(result):
    """Auth failures: one row per failure with AP, client, code, and description."""
    print("    Building Auth Failures CSV...")
    rows = []
    for ap, failures in result.auth_failures.items():
        for ts, client, code, short, desc in failures:
            rows.append({
                "Timestamp":   ts,
                "AP_BSSID":    ap,
                "ClientMAC":   client,
                "StatusCode":  code,
                "ShortName":   short,
                "Description": desc,
            })
    return pd.DataFrame(rows)


def _build_assoc_failures_df(result):
    """Assoc failures: one row per failure with AP, client, code, and description."""
    print("    Building Assoc Failures CSV...")
    rows = []
    for ap, failures in result.assoc_failures.items():
        for ts, client, code, short, desc in failures:
            rows.append({
                "Timestamp":   ts,
                "AP_BSSID":    ap,
                "ClientMAC":   client,
                "StatusCode":  code,
                "ShortName":   short,
                "Description": desc,
            })
    return pd.DataFrame(rows)


def _build_deauth_events_df(result):
    """Deauth events: one row per event with AP, client, reason code, and description."""
    print("    Building Deauth Events CSV...")
    rows = []
    for ap, events in result.deauth_events.items():
        for ts, client, code, short, desc in events:
            rows.append({
                "Timestamp":   ts,
                "AP_BSSID":    ap,
                "ClientMAC":   client,
                "ReasonCode":  code,
                "ShortName":   short,
                "Description": desc,
            })
    return pd.DataFrame(rows)


def _build_disassoc_events_df(result):
    """Disassoc events: one row per event with AP, client, reason code, and description."""
    print("    Building Disassoc Events CSV...")
    rows = []
    for ap, events in result.disassoc_events.items():
        for ts, client, code, short, desc in events:
            rows.append({
                "Timestamp":   ts,
                "AP_BSSID":    ap,
                "ClientMAC":   client,
                "ReasonCode":  code,
                "ShortName":   short,
                "Description": desc,
            })
    return pd.DataFrame(rows)


def _build_client_event_timeline_df(result):
    """
    Per-client chronological event log combining auth, assoc, deauth,
    and disassoc events into one sorted timeline.
    """
    print("    Building Client Event Timeline CSV...")
    rows = []
    for client, events in result.client_event_timeline.items():
        for ts, ap, event_type, code, desc in sorted(events, key=lambda x: x[0]):
            rows.append({
                "Timestamp":   ts,
                "ClientMAC":   client,
                "AP_BSSID":    ap,
                "EventType":   event_type,
                "Code":        code,
                "Description": desc,
            })
    return pd.DataFrame(rows)


def _build_dhcp_sessions_df(result):
    """One row per DHCP transaction showing the full session lifecycle."""
    print("    Building DHCP Sessions CSV...")
    rows = []
    for session in result.dhcp_sessions.values():
        rows.append({
            "ClientMAC":      session.client_mac,
            "TransactionID":  session.transaction_id,
            "DiscoverTime":   session.discover_time,
            "OfferTime":      session.offer_time,
            "OfferedIP":      session.offer_ip,
            "OfferServer":    session.offer_server,
            "RequestTime":    session.request_time,
            "AckTime":        session.ack_time,
            "AssignedIP":     session.assigned_ip,
            "LeaseTime":      session.lease_time,
            "Completed":      session.completed,
            "Failed":         session.failed,
            "FailureReason":  session.failure_reason,
            "DiscoverToAckSeconds": (
                round(session.ack_time - session.discover_time, 3)
                if session.discover_time and session.ack_time else None
            ),
        })
    return pd.DataFrame(rows)


# ----------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------

def _write(df, filename, out_dir):
    path = os.path.join(out_dir, filename)
    df.to_csv(path, index=False)
    print(f"      Wrote {filename}")


def _mode_band(df, bssid=None, source=None, ssid=None):
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
