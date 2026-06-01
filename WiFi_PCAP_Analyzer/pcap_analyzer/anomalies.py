# ================================================================
#  anomalies.py
#  Anomaly detection engine.
#  Takes a PcapResult and returns a list of human-readable anomaly strings.
# ================================================================

from .oui import lookup_vendor
from .mac_utils import is_randomized_mac
from .status_codes import is_infrastructure_fault_status, is_infrastructure_fault_reason
from .dhcp_parser import analyze_dhcp_sessions


def detect_anomalies(result, oui_db):
    """
    Run all anomaly checks against the processed capture data.

    Parameters
    ----------
    result  : PcapResult from processor.process_packets()
    oui_db  : OUI vendor lookup dict

    Returns a sorted list of anomaly description strings.
    """
    anomalies = []
    df = result.df

    anomalies.extend(_check_rogue_aps(result, oui_db))
    anomalies.extend(_check_evil_twins(result, oui_db))
    anomalies.extend(_check_probe_bursts(result))
    anomalies.extend(_check_suspicious_roaming(result))
    anomalies.extend(_check_randomized_mac_abuse(result))
    anomalies.extend(_check_ap_load_spikes(result))
    anomalies.extend(_check_deauth_attacks(df))
    anomalies.extend(_check_disassoc_attacks(df))
    anomalies.extend(_check_rssi_anomalies(result))
    anomalies.extend(_check_auth_failure_patterns(result))
    anomalies.extend(_check_assoc_failure_patterns(result))
    anomalies.extend(_check_infrastructure_faults(result))
    anomalies.extend(analyze_dhcp_sessions(result.dhcp_sessions))

    return sorted(anomalies)


# ----------------------------------------------------------------
# Individual anomaly checks
# ----------------------------------------------------------------

def _check_rogue_aps(result, oui_db):
    """Flag APs with an unknown vendor and zero clients."""
    found = []
    for ap, info in result.ap_client_map.items():
        ssid = info["SSID"]
        clients = info["Clients"]
        vendor = lookup_vendor(ap, oui_db)
        if vendor == "Unknown Vendor" and len(clients) == 0:
            found.append(
                f"Rogue AP suspected: {ap} broadcasting SSID={ssid} "
                f"with unknown vendor and no clients"
            )
    return found


def _check_evil_twins(result, oui_db):
    """Flag SSIDs broadcast by multiple APs from different vendors."""
    found = []
    for ssid, bssids in result.ssid_to_bssids.items():
        if len(bssids) > 1:
            vendors = {lookup_vendor(b, oui_db) for b in bssids}
            if len(vendors) > 1:
                found.append(
                    f"Evil Twin suspected: SSID={ssid} broadcast by "
                    f"multiple vendors: {sorted(bssids)}"
                )
    return found


def _check_probe_bursts(result):
    """Flag clients that sent 6+ probe requests in under 1 second."""
    found = []
    for client, times in result.probe_times.items():
        times_sorted = sorted(times)
        for i in range(len(times_sorted) - 5):
            if times_sorted[i + 5] - times_sorted[i] < 1.0:
                found.append(
                    f"Probe burst: {client} sent 6+ probe requests in under 1 second"
                )
                break
    return found


def _check_suspicious_roaming(result):
    """Flag clients that roamed 4+ times in under 10 seconds."""
    found = []
    for client, events in result.roaming_events.items():
        events_sorted = sorted(events, key=lambda x: x[3])
        for i in range(len(events_sorted) - 3):
            if events_sorted[i + 3][3] - events_sorted[i][3] < 10:
                found.append(
                    f"Suspicious roaming: {client} roamed 4+ times in under 10 seconds"
                )
                break
    return found


def _check_randomized_mac_abuse(result):
    """Flag randomized MACs that sent data frames or performed roaming."""
    found = []
    df = result.df
    for mac in result.randomized_macs:
        client_rows = df[df["Source"] == mac]
        if any(client_rows["Type"] == 2):
            found.append(f"Randomized MAC {mac} sent data frames (unusual behavior)")
        if mac in result.roaming_events:
            found.append(f"Randomized MAC {mac} performed roaming (very unusual)")
    return found


def _check_ap_load_spikes(result):
    """Flag APs whose client count tripled in under 2 seconds."""
    found = []
    for ap, entries in result.ap_load_timeline.items():
        entries_sorted = sorted(entries, key=lambda x: x[0])
        for i in range(len(entries_sorted) - 1):
            t1, c1 = entries_sorted[i]
            t2, c2 = entries_sorted[i + 1]
            if c1 > 0 and c2 / max(c1, 1) > 3 and (t2 - t1) < 2:
                found.append(
                    f"AP Load Spike: {ap} jumped from {c1} to {c2} clients in under 2 seconds"
                )
                break
    return found


def _check_deauth_attacks(df):
    """Flag possible deauthentication flood attacks (subtype 12)."""
    found = []
    deauth_frames = df[(df["Type"] == 0) & (df["Subtype"] == 12)]
    if deauth_frames.empty:
        return found

    if len(deauth_frames) > 50:
        found.append(
            f"Possible deauthentication attack: {len(deauth_frames)} deauth frames observed"
        )

    for src_mac, group in deauth_frames.groupby("Source"):
        times = sorted(group["Timestamp"])
        for i in range(len(times) - 9):
            if times[i + 9] - times[i] < 5:
                found.append(
                    f"Deauth flood suspected from {src_mac}: "
                    f"10+ deauth frames in under 5 seconds"
                )
                break

    return found


def _check_disassoc_attacks(df):
    """Flag possible disassociation flood attacks (subtype 10)."""
    found = []
    disassoc_frames = df[(df["Type"] == 0) & (df["Subtype"] == 10)]
    if disassoc_frames.empty:
        return found

    if len(disassoc_frames) > 50:
        found.append(
            f"Possible disassociation attack: {len(disassoc_frames)} disassociation frames observed"
        )

    for src_mac, group in disassoc_frames.groupby("Source"):
        times = sorted(group["Timestamp"])
        for i in range(len(times) - 9):
            if times[i + 9] - times[i] < 5:
                found.append(
                    f"Disassociation flood suspected from {src_mac}: "
                    f"10+ disassociation frames in under 5 seconds"
                )
                break

    return found


def _check_rssi_anomalies(result):
    """Flag clients whose signal jumped more than 25 dB in under 2 seconds."""
    found = []
    for client, samples in result.client_rssi.items():
        samples_sorted = sorted(samples, key=lambda x: x[0])
        for i in range(len(samples_sorted) - 1):
            t1, r1 = samples_sorted[i]
            t2, r2 = samples_sorted[i + 1]
            if r1 is not None and r2 is not None:
                if abs(r2 - r1) > 25 and (t2 - t1) < 2:
                    found.append(
                        f"RSSI anomaly: {client} signal changed by "
                        f"{abs(r2 - r1)} dB in under 2 seconds"
                    )
                    break
    return found


def _check_auth_failure_patterns(result):
    """
    Flag APs with repeated auth failures and clients failing across
    multiple APs (credential problem vs infrastructure problem).
    """
    found = []

    # AP with 5+ auth failures — AP-side or RADIUS problem
    for ap, failures in result.auth_failures.items():
        if len(failures) >= 5:
            codes = [f[2] for f in failures]
            most_common_code = max(set(codes), key=codes.count)
            _, desc = _lookup_status_safe(most_common_code)
            found.append(
                f"Auth failure pattern on AP {ap}: {len(failures)} failures, "
                f"most common cause — {desc}"
            )

    # Client failing auth on 3+ different APs — likely a credential issue
    client_ap_failures = {}
    for ap, failures in result.auth_failures.items():
        for ts, client, code, short, desc in failures:
            client_ap_failures.setdefault(client, set()).add(ap)
    for client, aps in client_ap_failures.items():
        if len(aps) >= 3:
            found.append(
                f"Client {client} failed authentication on {len(aps)} different APs "
                f"— likely a credential or certificate issue on the client"
            )

    return found


def _check_assoc_failure_patterns(result):
    """
    Flag APs repeatedly rejecting associations and specific failure
    codes that point to infrastructure misconfigurations.
    """
    found = []

    for ap, failures in result.assoc_failures.items():
        if len(failures) >= 3:
            codes = [f[2] for f in failures]
            most_common_code = max(set(codes), key=codes.count)
            _, desc = _lookup_status_safe(most_common_code)
            found.append(
                f"Assoc failure pattern on AP {ap}: {len(failures)} failures, "
                f"most common cause — {desc}"
            )

        # AP_FULL (code 17) repeatedly = capacity planning issue
        full_count = sum(1 for f in failures if f[2] == 17)
        if full_count >= 3:
            found.append(
                f"AP {ap} rejected {full_count} clients due to being full "
                f"— review client density limits or add APs"
            )

    return found


def _check_infrastructure_faults(result):
    """
    Flag status and reason codes that specifically indicate infrastructure
    problems rather than client problems. These warrant immediate escalation.
    """
    found = []

    # Check auth failures for infrastructure fault codes
    for ap, failures in result.auth_failures.items():
        for ts, client, code, short, desc in failures:
            if is_infrastructure_fault_status(code):
                found.append(
                    f"Infrastructure fault — AP {ap} rejected {client} "
                    f"with {short}: {desc}"
                )

    # Check assoc failures for infrastructure fault codes
    for ap, failures in result.assoc_failures.items():
        for ts, client, code, short, desc in failures:
            if is_infrastructure_fault_status(code):
                found.append(
                    f"Infrastructure fault — AP {ap} rejected {client} "
                    f"with {short}: {desc}"
                )

    # Check deauth events for infrastructure fault reason codes
    for ap, events in result.deauth_events.items():
        for ts, client, code, short, desc in events:
            if is_infrastructure_fault_reason(code):
                found.append(
                    f"Infrastructure fault — AP {ap} deauthed {client} "
                    f"with reason {short}: {desc}"
                )

    return found


# ----------------------------------------------------------------
# Shared helper (avoids importing status_codes into this scope twice)
# ----------------------------------------------------------------

def _lookup_status_safe(code):
    """Thin wrapper so anomaly functions can look up status codes."""
    from .status_codes import lookup_status
    return lookup_status(code)
