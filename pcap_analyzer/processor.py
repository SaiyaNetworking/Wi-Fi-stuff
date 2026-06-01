# ================================================================
#  processor.py
#  Core packet processing logic.
#  Reads PCAP files and returns a PcapResult dataclass containing
#  all derived data structures, replacing all former global variables.
# ================================================================

from dataclasses import dataclass, field
from scapy.all import (
    rdpcap, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, RadioTap,
    Dot11Auth, Dot11AssoResp, Dot11ReassoResp, Dot11Deauth, Dot11Disas,
)
import pandas as pd

from .filters import packet_passes_filters
from .mac_utils import is_randomized_mac
from .freq_utils import channel_to_frequency, frequency_to_band
from .oui import lookup_vendor
from .status_codes import lookup_status, lookup_reason, is_failure_status
from .dhcp_parser import is_dhcp_packet, parse_dhcp_packet


# ----------------------------------------------------------------
# PcapResult: the single object that flows through the entire program
# ----------------------------------------------------------------

@dataclass
class PcapResult:
    """
    All data derived from processing one or more PCAP files.
    Replaces the scattered global variables of the original script.
    """
    # The main DataFrame: one row per processed packet
    df: pd.DataFrame = field(default_factory=pd.DataFrame)

    # AP BSSID → {"SSID": str, "Clients": set()}
    ap_client_map: dict = field(default_factory=dict)

    # client MAC → list of (timestamp, rssi)
    client_rssi: dict = field(default_factory=dict)

    # client MAC → list of (old_ap, new_ap, ssid, timestamp)
    roaming_events: dict = field(default_factory=dict)

    # AP MAC → "<hidden>" for APs that only broadcast empty SSIDs
    hidden_ssids: dict = field(default_factory=dict)

    # AP MAC → real SSID (learned from probe responses)
    revealed_ssids: dict = field(default_factory=dict)

    # Randomized MAC → set of (ssid, bssid) tuples
    randomized_associations: dict = field(default_factory=dict)

    # Set of all randomized MAC addresses observed
    randomized_macs: set = field(default_factory=set)

    # Band name → bool: which bands were observed at all
    observed_bands: dict = field(default_factory=lambda: {
        "2.4GHz": False, "5GHz": False, "6GHz": False
    })

    # client MAC → list of timestamps of probe requests
    probe_times: dict = field(default_factory=dict)

    # SSID → list of timestamps
    ssid_activity: dict = field(default_factory=dict)

    # AP BSSID → list of (timestamp, client_count)
    ap_load_timeline: dict = field(default_factory=dict)

    # client MAC → first timestamp seen
    client_first_seen: dict = field(default_factory=dict)

    # client MAC → last timestamp seen
    client_last_seen: dict = field(default_factory=dict)

    # SSID → set of BSSIDs broadcasting it
    ssid_to_bssids: dict = field(default_factory=dict)

    # Total number of packets processed (after filters and limit)
    processed_packets: int = 0

    # ---- Management frame status / reason codes ----

    # AP BSSID → list of (timestamp, client_mac, code, short_name, description)
    auth_failures: dict = field(default_factory=dict)
    assoc_failures: dict = field(default_factory=dict)

    # AP BSSID → list of (timestamp, client_mac, code, short_name, description)
    deauth_events: dict = field(default_factory=dict)
    disassoc_events: dict = field(default_factory=dict)

    # client MAC → chronological list of (timestamp, ap_bssid, event_type, code, description)
    client_event_timeline: dict = field(default_factory=dict)

    # ---- DHCP session tracking ----

    # transaction_id (int) → DHCPSession
    dhcp_sessions: dict = field(default_factory=dict)

    # flat list of dicts — one entry per DHCP message, used for CSV export
    dhcp_events: list = field(default_factory=list)


# ----------------------------------------------------------------
# Main processing entry point
# ----------------------------------------------------------------

def process_packets(pcaps, args, oui_db):
    """
    Iterate over all PCAP files, process each packet, and return a PcapResult.

    Parameters
    ----------
    pcaps   : list of PCAP file paths to process
    args    : parsed CLI args (from cli.parse_args())
    oui_db  : OUI vendor lookup dict (from oui.load_oui_database())
    """
    result = PcapResult()
    records = []

    for pcap in pcaps:
        print(f"\nLoading PCAP: {pcap}")
        packets = rdpcap(pcap)
        total_packets = len(packets)
        print(f"Total packets detected in this file: {total_packets:,}\n")

        for idx, pkt in enumerate(packets):
            # Enforce global packet limit across all files
            if args.limit is not None and result.processed_packets >= args.limit:
                print(f"\nPacket limit of {args.limit} reached; stopping.")
                break

            # Progress indicator every 5000 packets
            if idx % 5000 == 0:
                pct = (idx / total_packets) * 100 if total_packets > 0 else 0
                print(f"  {pct:5.1f}% ({idx:,}/{total_packets:,}) in {pcap}")

            if not pkt.haslayer(Dot11):
                continue

            if not packet_passes_filters(pkt, args.filter):
                continue

            result.processed_packets += 1

            record = _process_single_packet(pkt, result, oui_db)
            records.append(record)

        if args.limit is not None and result.processed_packets >= args.limit:
            break

    print(f"\nTotal processed packets (after filters and limit): {result.processed_packets:,}")
    print("\nBuilding DataFrame...")

    result.df = pd.DataFrame(records)

    # Replace hidden SSIDs with revealed ones where possible
    for ap_mac, _hidden in result.hidden_ssids.items():
        if ap_mac in result.revealed_ssids:
            result.df.loc[result.df["BSSID"] == ap_mac, "SSID"] = result.revealed_ssids[ap_mac]

    # Build SSID → set of BSSIDs map
    for ap, info in result.ap_client_map.items():
        ssid = info.get("SSID")
        if ssid not in [None, "", "<hidden>"]:
            result.ssid_to_bssids.setdefault(ssid, set()).add(ap)

    # Collect all randomized MACs into a flat set for easy lookup
    if not result.df.empty:
        result.randomized_macs = set(
            result.df[result.df["Randomized"] == True]["Source"].dropna().unique()
        )

    return result


# ----------------------------------------------------------------
# Single-packet processing (called once per packet in the loop)
# ----------------------------------------------------------------

def _process_single_packet(pkt, result, oui_db):
    """
    Extract all relevant fields from one packet, update the result
    data structures in place, and return a record dict for the DataFrame.
    """
    dot11 = pkt[Dot11]

    src           = pkt.addr2
    dst           = pkt.addr1
    bssid         = pkt.addr3
    frame_type    = dot11.type
    frame_subtype = dot11.subtype
    timestamp     = pkt.time
    ssid          = None

    # --- Channel / Frequency ---
    freq_mhz, channel = _extract_frequency(pkt)

    if freq_mhz is None and channel is not None:
        freq_mhz = channel_to_frequency(channel)

    _update_observed_bands(freq_mhz, result.observed_bands)

    # --- RSSI ---
    try:
        rssi = pkt.dBm_AntSignal
    except Exception:
        rssi = None

    # --- SSID extraction ---
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        raw_ssid = pkt.info.decode(errors="ignore")
        if raw_ssid == "" or raw_ssid is None:
            result.hidden_ssids[bssid] = "<hidden>"
            ssid = "<hidden>"
        else:
            ssid = raw_ssid

    elif pkt.haslayer(Dot11ProbeReq):
        raw_ssid = pkt.info.decode(errors="ignore")
        if raw_ssid not in ["", None]:
            result.revealed_ssids[bssid] = raw_ssid
        ssid = raw_ssid

    # Ensure the AP map records the SSID when known
    if ssid not in [None, "", "<hidden>"] and bssid:
        result.ap_client_map.setdefault(bssid, {"SSID": None, "Clients": set()})
        result.ap_client_map[bssid]["SSID"] = ssid

    # --- Randomized MAC associations ---
    if is_randomized_mac(src) and ssid not in [None, "", "<hidden>"]:
        result.randomized_associations.setdefault(src, set()).add((ssid, bssid))

    # --- AP–Client mapping ---
    _update_ap_client_map(frame_type, frame_subtype, src, bssid, result.ap_client_map)

    # --- Roaming detection ---
    _detect_roaming(src, bssid, ssid, timestamp, result)

    # --- Time-based tracking ---
    if src:
        result.client_first_seen.setdefault(src, timestamp)
        result.client_last_seen[src] = timestamp

    if ssid not in [None, "", "<hidden>"]:
        result.ssid_activity.setdefault(ssid, []).append(timestamp)

    if bssid in result.ap_client_map:
        count = len(result.ap_client_map[bssid]["Clients"])
        result.ap_load_timeline.setdefault(bssid, []).append((timestamp, count))

    if src:
        result.client_rssi.setdefault(src, []).append((timestamp, rssi))

    # Track probe request timestamps for burst detection later
    if frame_type == 0 and frame_subtype == 4 and src:
        result.probe_times.setdefault(src, []).append(timestamp)

    # --- Management frame status / reason code parsing ---
    _parse_mgmt_codes(pkt, src, bssid, timestamp, frame_type, frame_subtype, result)

    # --- DHCP parsing (data frames carrying UDP/67-68) ---
    if frame_type == 2 and is_dhcp_packet(pkt):
        parse_dhcp_packet(pkt, timestamp, result.dhcp_sessions, result.dhcp_events)

    return {
        "Source":           src,
        "SourceVendor":     lookup_vendor(src, oui_db),
        "Destination":      dst,
        "DestinationVendor": lookup_vendor(dst, oui_db),
        "BSSID":            bssid,
        "SSID":             ssid,
        "Type":             frame_type,
        "Subtype":          frame_subtype,
        "Randomized":       is_randomized_mac(src),
        "Timestamp":        timestamp,
        "RSSI":             rssi,
        "Channel":          channel,
        "FrequencyMHz":     freq_mhz,
        "Band":             frequency_to_band(freq_mhz),
    }


# ----------------------------------------------------------------
# Private helpers
# ----------------------------------------------------------------

def _extract_frequency(pkt):
    """
    Try to extract frequency (MHz) and channel from a packet.
    Returns (freq_mhz, channel) — either may be None.
    """
    freq_mhz = None
    channel  = None

    # RadioTap header carries frequency directly
    try:
        rt = pkt[RadioTap]
        freq_mhz = getattr(rt, "ChannelFrequency", None)
    except Exception:
        pass

    # Beacon and probe response frames carry the channel in network stats
    try:
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get("channel")
    except Exception:
        pass

    return freq_mhz, channel


def _update_observed_bands(freq_mhz, observed_bands):
    """Mark which frequency bands have been seen in this capture."""
    if freq_mhz is None:
        return
    if 2400 <= freq_mhz < 2500:
        observed_bands["2.4GHz"] = True
    elif 5000 <= freq_mhz < 5900:
        observed_bands["5GHz"] = True
    elif 5900 <= freq_mhz < 7125:
        observed_bands["6GHz"] = True


def _update_ap_client_map(frame_type, frame_subtype, src, bssid, ap_client_map):
    """
    Update the AP→clients mapping based on association, re-association,
    authentication, and data frames.
    """
    if frame_type == 0 and frame_subtype in [0, 2, 11]:  # Assoc / Reassoc / Auth
        ap_client_map.setdefault(bssid, {"SSID": None, "Clients": set()})
        ap_client_map[bssid]["Clients"].add(src)

    if frame_type == 2:  # Data frame
        ap_client_map.setdefault(bssid, {"SSID": None, "Clients": set()})
        ap_client_map[bssid]["Clients"].add(src)


def _detect_roaming(src, bssid, ssid, timestamp, result):
    """
    Detect when a client moves from one AP to another (roaming).
    Updates result.roaming_events and result's internal last_ap_seen tracking.
    """
    # We use a private dict stored on the result for last-seen AP per client
    if not hasattr(result, "_last_ap_seen"):
        result._last_ap_seen = {}

    if src and bssid and src != bssid:
        if src in result._last_ap_seen:
            old_ap = result._last_ap_seen[src]
            if old_ap != bssid and ssid not in [None, "", "<hidden>"]:
                result.roaming_events.setdefault(src, []).append(
                    (old_ap, bssid, ssid, timestamp)
                )
        result._last_ap_seen[src] = bssid


def _parse_mgmt_codes(pkt, src, bssid, timestamp, frame_type, frame_subtype, result):
    """
    Extract status and reason codes from auth, assoc, reassoc, deauth,
    and disassoc frames. Updates auth_failures, assoc_failures,
    deauth_events, disassoc_events, and client_event_timeline on result.
    """
    # Only management frames carry these codes
    if frame_type != 0:
        return

    # Auth response (subtype 11) — sent by AP back to client
    if frame_subtype == 11 and pkt.haslayer(Dot11Auth):
        code = pkt[Dot11Auth].status
        short, desc = lookup_status(code)
        if is_failure_status(code):
            result.auth_failures.setdefault(bssid, []).append(
                (timestamp, src, code, short, desc)
            )
            result.client_event_timeline.setdefault(src, []).append(
                (timestamp, bssid, "AUTH_FAILURE", code, desc)
            )

    # Assoc response (subtype 1)
    elif frame_subtype == 1 and pkt.haslayer(Dot11AssoResp):
        code = pkt[Dot11AssoResp].status
        short, desc = lookup_status(code)
        if is_failure_status(code):
            result.assoc_failures.setdefault(bssid, []).append(
                (timestamp, src, code, short, desc)
            )
            result.client_event_timeline.setdefault(src, []).append(
                (timestamp, bssid, "ASSOC_FAILURE", code, desc)
            )

    # Reassoc response (subtype 3)
    elif frame_subtype == 3 and pkt.haslayer(Dot11ReassoResp):
        code = pkt[Dot11ReassoResp].status
        short, desc = lookup_status(code)
        if is_failure_status(code):
            result.assoc_failures.setdefault(bssid, []).append(
                (timestamp, src, code, short, desc)
            )
            result.client_event_timeline.setdefault(src, []).append(
                (timestamp, bssid, "REASSOC_FAILURE", code, desc)
            )

    # Deauth (subtype 12)
    elif frame_subtype == 12 and pkt.haslayer(Dot11Deauth):
        code = pkt[Dot11Deauth].reason
        short, desc = lookup_reason(code)
        result.deauth_events.setdefault(bssid, []).append(
            (timestamp, src, code, short, desc)
        )
        result.client_event_timeline.setdefault(src, []).append(
            (timestamp, bssid, "DEAUTH", code, desc)
        )

    # Disassoc (subtype 10)
    elif frame_subtype == 10 and pkt.haslayer(Dot11Disas):
        code = pkt[Dot11Disas].reason
        short, desc = lookup_reason(code)
        result.disassoc_events.setdefault(bssid, []).append(
            (timestamp, src, code, short, desc)
        )
        result.client_event_timeline.setdefault(src, []).append(
            (timestamp, bssid, "DISASSOC", code, desc)
        )
