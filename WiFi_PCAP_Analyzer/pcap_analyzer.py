# ================================================================
#  Wireless PCAP Analyzer
#  Wi‑Fi reconnaissance and reporting toolkit
# ================================================================
#  Features:
#    • Parse and analyze 802.11 PCAP files using Scapy + Pandas
#    • Detect hidden SSIDs, randomized MACs, roaming, and anomalies
#    • Map AP–Client relationships with vendor identification
#    • Extract RSSI, channels, frequencies, and band usage (2.4/5/6 GHz)
#    • Generate TXT and CSV reports, including a dedicated wardriving table
#
#  Modes:
#    • Default: full analysis + all reports
#    • --summary-only: lightweight TXT summary
#    • --wardrive: ultra-fast wardriving output (TXT + CSV only)
#
#  Tips:
#    • Use --no-csv for large captures to speed up processing
#    • Use "?" for quick help (alias for -h)
# ================================================================



import argparse             # Used for user interface in the CLI
import glob                 # Used for file path expansion (wildcards, directories)
import os                   # Used for file path manipulation and directory creation with the --out argument
import sys                  # Used only for the "?" help shortcut. You can comment out if uncertain along with the:
                                    # if len(sys.argv) == 2 and sys.argv[1] == "?":
                                        # sys.argv[1] = "-h
                            # Lines to remove the "import sys" package from the program.


from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, RadioTap      # Backbone of the program for Wi-Fi reads
import pandas as pd                                                                            # Backbone of the data breakdown

VERSION = "1.0.0"

# ----------------- ARGUMENT PARSING -----------------

if len(sys.argv) == 2 and sys.argv[1] == "?":           # Comment these out if you don't want the sys library running
    sys.argv[1] = "-h"                                  # This too

parser = argparse.ArgumentParser(
    prog="pcap_analyzer.py",
    description=(
        "Wireless PCAP Analyzer\n"
        "Analyze Wi‑Fi PCAP files and export structured TXT and CSV reports.\n\n"
        "Quick start:\n"
        "  pcap_analyzer.py --pcap filename.pcap\n\n"
        "Examples:\n"
        "  Analyze a single PCAP:\n"
        "      pcap_analyzer.py --pcap filename.pcap\n\n"
        "  Analyze all PCAPs in a folder:\n"
        "      pcap_analyzer.py --pcap logs/\n\n"
        "  Export only frames and AP summaries:\n"
        "      pcap_analyzer.py --pcap filename.pcap --csv-list frames,aps\n\n"
        "  Skip CSVs for faster runs:\n"
        "      pcap_analyzer.py --pcap filename.pcap --no-csv\n"
    ),
    epilog=(
        "Performance Tips:\n"
        "  • Use --no-csv for large captures to skip heavy CSV generation\n"
        "  • Use --limit <n> to cap packet processing for quick previews\n"
        "  • Use --filter to reduce workload (e.g., --filter ssid=HomeNetwork)\n"
        "  • TXT-only mode (--no-csv) is significantly faster for >10k packets\n"
        "  • CSV exports like rssi_timeline and frames are the heaviest\n"
    ),
    formatter_class=argparse.RawDescriptionHelpFormatter,
)

# ---- Input Options ----
input_group = parser.add_argument_group("Input Options")
input_group.add_argument(
    "--pcap",
    nargs="+",
    help="PCAP file(s), wildcard(s), or folders to analyze",
)
input_group.add_argument(
    "--limit",
    type=int,
    help="Optional global packet limit",
)
input_group.add_argument(
    "--filter",
    action="append",
    help="Frame filter(s): ssid=..., mac=..., type=..., subtype=... (can be repeated)",
)

# ---- Output Options ----
output_group = parser.add_argument_group("Output Options")
output_group.add_argument(
    "--out",
    default=".",
    help="Output directory for TXT and CSV files (default: current directory)",
)
output_group.add_argument(
    "--summary-only",
    action="store_true",
    help="Generate a lightweight TXT summary only",
)
output_group.add_argument(
    "--wardrive",
    action="store_true",
    help="Output only the wardriving table (no full summary)"
)
output_group.add_argument(
    "--no-txt",
    action="store_true",
    help="Skip TXT export",
)
output_group.add_argument(
    "--no-csv",
    action="store_true",
    help="Skip CSV exports",
)

# ---- CSV Control ----
csv_group = parser.add_argument_group("CSV Control")
csv_group.add_argument(
    "--csv-list",
    type=str,
    help="Export only specific CSVs (comma-separated)",
)
csv_group.add_argument(
    "--list-csv",
    action="store_true",
    help="List all available CSV export names and exit",
)

# ---- General ----
general_group = parser.add_argument_group("General")
general_group.add_argument(
    "--version",
    action="version",
    version=f"Wireless PCAP Analyzer {VERSION}",
    help="Show version and exit",
)
general_group.add_argument(
    "--help-filters",
    action="store_true",
    help="Show help and examples for --filter usage and exit",
)

args = parser.parse_args()

WARDIVE_MODE = args.wardrive



# ----------------- CSV / FILTER HELP & VALIDATION -----------------

# CSV names and descriptions
csv_descriptions = {
    "frames": "All captured frames with metadata",
    "clients": "Per-client summary (first/last seen, RSSI stats)",
    "aps": "Access point summary (SSID, vendor, client count)",
    "anomalies": "High-level anomaly descriptions",
    "roaming": "Roaming events with timestamps",
    "rssi_timeline": "Per-client RSSI timeline (timestamp → RSSI)",
    "ssid_activity": "SSID activity windows and frame counts",
    "ap_load_timeline": "AP client load over time",
    "randomized_associations": "Randomized MAC → SSID/BSSID associations",
    "frequencies": "Per-frame channel, frequency, and band",
    "wardrive": "Wardriving table (SSID, BSSID, channel, band, RSSI, clients, vendor, notes)",
}

valid_csvs = set(csv_descriptions.keys())

# If user only wants to see filter help, print and exit early
if args.help_filters:
    print("=== Filter Help ===\n")
    print("You can use --filter to limit which frames are analyzed.")
    print("Filters can be repeated; all filters must match for a frame to pass.\n")
    print("Supported keys:")
    print("  ssid=<name>       Match frames for a specific SSID")
    print("  mac=<address>     Match if MAC appears in addr1/addr2/addr3")
    print("  type=<n>          Match Dot11 frame type (0=mgmt, 1=control, 2=data)")
    print("  subtype=<n>       Match Dot11 frame subtype (e.g., 4=ProbeReq)\n")
    print("Examples:")
    print("  Only frames for a specific SSID:")
    print("      --filter ssid=HomeNetwork")
    print("  Only frames involving a specific MAC:")
    print("      --filter mac=aa:bb:cc:dd:ee:ff")
    print("  Only probe requests:")
    print("      --filter type=0 --filter subtype=4")
    print("  Combine filters (SSID + type):")
    print("      --filter ssid=HomeNetwork --filter type=2\n")
    raise SystemExit(0)

# If user only wants to list CSV names, do it and exit early
if args.list_csv:
    print("Available CSV exports:\n")
    for name in sorted(valid_csvs):
        desc = csv_descriptions.get(name, "")
        print(f"  {name:<22} {desc}")
    raise SystemExit(0)

# Require --pcap unless a help/list-only flag was used
if not args.pcap:
    raise SystemExit("Error: --pcap is required unless \"?\", -h, --list-csv or --help-filters is used.")

# Parse CSV list argument
if args.csv_list:
    requested_csvs = {name.strip().lower() for name in args.csv_list.split(",")}
else:
    requested_csvs = None  # Means export all CSVs unless --no-csv is used
if args.wardrive:
    requested_csvs = {"wardrive"}

# Validate CSV names if a list was provided
if requested_csvs is not None:
    unknown = requested_csvs - valid_csvs
    if unknown:
        print("Error: The following CSV names are not recognized:")
        for name in sorted(unknown):
            print(f"  - {name}")

        print("\nValid CSV names are:")
        print("  " + ", ".join(sorted(valid_csvs)))
        print("\nPlease correct the CSV names and try again.")
        raise SystemExit(1)

# Expand PCAP arguments into a concrete list of files
pcaps = []
for item in args.pcap:
    if os.path.isdir(item):
        pcaps.extend(glob.glob(os.path.join(item, "*.pcap")))
    else:
        # Handles explicit files and wildcards
        pcaps.extend(glob.glob(item))

if not pcaps:
    raise SystemExit("No PCAP files found for the given --pcap argument(s).")

# Ensure output directory exists
os.makedirs(args.out, exist_ok=True)

# ----------------- HELPER FUNCTIONS -----------------

# Load separate OUI MAC database text file to map MAC addresses to vendors
def load_oui_database(path="oui.txt"):
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
    if mac is None:
        return "Unknown Vendor"
    prefix = mac.upper()[0:8]
    return oui_map.get(prefix, "Unknown Vendor")

# MAC randomization detection
def is_randomized_mac(mac):
    if mac is None:
        return False
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0b00000010)
    except:
        return False

# Packet filter based on CLI --filter arguments
def packet_passes_filters(pkt):
    # No filters → everything passes
    if not args.filter:
        return True

    # Only process Dot11 frames for filtering
    if not pkt.haslayer(Dot11):
        return False

    dot11 = pkt[Dot11]

    for flt in args.filter:
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

        # Unknown keys are ignored

    return True

# ----------------- FREQUENCY / BAND HELPERS -----------------

def channel_to_frequency(channel):
    """Convert Wi-Fi channel number to an approximate center frequency in MHz."""
    if channel is None:
        return None

    # 2.4 GHz band (channels 1–14)
    if 1 <= channel <= 14:
        # Channel 1 = 2412 MHz → 2412 + 5*(channel-1)
        return 2412 + 5 * (channel - 1)

    # 5 GHz band (common UNII channels)
    if 36 <= channel <= 177:
        # Rough mapping: 5000 + 5*channel (e.g., 36 → 5180)
        return 5000 + 5 * channel

    # 6 GHz band (Wi‑Fi 6E) – approximate
    if 1 <= channel <= 233:
        # Simplified: 5955 + 5*(channel-1)
        return 5955 + 5 * (channel - 1)

    return None

def frequency_to_band(freq):
    if freq is None:
        return "Unknown"
    if 2400 <= freq < 2500:
        return "2.4GHz"
    if 5000 <= freq < 5900:
        return "5GHz"
    if 5900 <= freq < 7125:
        return "6GHz"
    return "Unknown"

# Helper: determine if a CSV should be exported
def should_export(name):
    if requested_csvs is None:
        return True
    return name.lower() in requested_csvs

# Track which bands were observed (any frame)
observed_bands = {
    "2.4GHz": False,
    "5GHz": False,
    "6GHz": False
}

# ----------------- GLOBAL STRUCTURES -----------------

# Load full OUI database
OUI_DB = load_oui_database("oui.txt")

records = []

hidden_ssids = {}             # AP MAC → "<hidden>"
revealed_ssids = {}           # AP MAC → real SSID
randomized_associations = {}  # Randomized MAC → set of (SSID, BSSID)
ap_client_map = {}            # AP BSSID → {"SSID": ssid, "Clients": set()}
last_ap_seen = {}             # client MAC → last BSSID
roaming_events = {}           # client MAC → list of (old_ap, new_ap, ssid, ts)

# Time-based structures
client_first_seen = {}        # MAC → first timestamp
client_last_seen = {}         # MAC → last timestamp
ssid_activity = {}            # SSID → list of timestamps
ap_load_timeline = {}         # AP BSSID → list of (timestamp, client_count)

# RSSI tracking
client_rssi = {}              # client MAC → list of (timestamp, rssi)

# ----------------- PACKET PROCESSING -----------------
processed_packets = 0

for pcap in pcaps:
    print(f"\nLoading PCAP: {pcap}")
    packets = rdpcap(pcap)

    print("Processing packets...")
    total_packets = len(packets)
    print(f"Total packets detected in this file: {total_packets:,}\n")

    for idx, pkt in enumerate(packets):
        # Global limit across all PCAPs
        if args.limit is not None and processed_packets >= args.limit:
            print(f"\nPacket limit of {args.limit} reached; stopping further processing.")
            break

        # Progress indicator every 5000 packets (per file)
        if idx % 5000 == 0:
            pct = (idx / total_packets) * 100 if total_packets > 0 else 0
            print(f"  {pct:5.1f}% complete ({idx:,}/{total_packets:,}) in {pcap}")

        if not pkt.haslayer(Dot11):
            continue

        if not packet_passes_filters(pkt):
            continue

        processed_packets += 1

        src = pkt.addr2
        dst = pkt.addr1
        ssid = None
        frame_type = pkt.type
        frame_subtype = pkt.subtype
        bssid = pkt.addr3  # AP MAC address
        timestamp = pkt.time

        # ----------------- CHANNEL / FREQUENCY EXTRACTION -----------------
        channel = None
        freq_mhz = None

        # Try radiotap: ChannelFrequency is already MHz if present
        try:
            rt = pkt[RadioTap]
            freq_mhz = getattr(rt, "ChannelFrequency", None)
        except:
            freq_mhz = None

        # Try to infer channel from beacon/probe frames
        if channel is None:
            try:
                if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                    stats = pkt[Dot11Beacon].network_stats()
                    channel = stats.get("channel")
            except:
                channel = None

        # If we have a channel but no frequency yet, derive it
        if freq_mhz is None and channel is not None:
            freq_mhz = channel_to_frequency(channel)

        # Track observed bands based on frequency
        if freq_mhz:
            if 2400 <= freq_mhz < 2500:
                observed_bands["2.4GHz"] = True
            elif 5000 <= freq_mhz < 5900:
                observed_bands["5GHz"] = True
            elif 5900 <= freq_mhz < 7125:
                observed_bands["6GHz"] = True

        # RSSI extraction (if available)
        try:
            rssi = pkt.dBm_AntSignal
        except:
            rssi = None

        # SSID extraction
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            raw_ssid = pkt.info.decode(errors="ignore")

            if raw_ssid == "" or raw_ssid is None:
                hidden_ssids[bssid] = "<hidden>"
                ssid = "<hidden>"
            else:
                ssid = raw_ssid

        elif pkt.haslayer(Dot11ProbeReq):
            raw_ssid = pkt.info.decode(errors="ignore")

            if raw_ssid not in ["", None]:
                revealed_ssids[bssid] = raw_ssid

            ssid = raw_ssid

        # Ensure AP map knows SSID when we actually learn it
        if ssid not in [None, "", "<hidden>"] and bssid:
            ap_client_map.setdefault(bssid, {"SSID": None, "Clients": set()})
            ap_client_map[bssid]["SSID"] = ssid

        # Track randomized MAC associations
        if is_randomized_mac(src):
            if ssid not in [None, "", "<hidden>"]:
                randomized_associations.setdefault(src, set()).add((ssid, bssid))

        # AP–Client association mapping
        if frame_type == 0 and frame_subtype in [0, 2]:  # Assoc / Reassoc
            ap_client_map.setdefault(bssid, {"SSID": None, "Clients": set()})
            ap_client_map[bssid]["Clients"].add(src)

        if frame_type == 0 and frame_subtype == 11:  # Authentication
            ap_client_map.setdefault(bssid, {"SSID": None, "Clients": set()})
            ap_client_map[bssid]["Clients"].add(src)

        if frame_type == 2:  # Data frame
            ap_client_map.setdefault(bssid, {"SSID": None, "Clients": set()})
            ap_client_map[bssid]["Clients"].add(src)

        # Roaming detection (with timestamps)
        if src and bssid and src != bssid:
            if src in last_ap_seen:
                old_ap = last_ap_seen[src]
                if old_ap != bssid and ssid not in [None, "", "<hidden>"]:

                    roaming_events.setdefault(src, []).append(
                        (old_ap, bssid, ssid, timestamp)
                    )
            last_ap_seen[src] = bssid

        # Time-based: client first/last seen
        if src:
            client_first_seen.setdefault(src, timestamp)
            client_last_seen[src] = timestamp

        # Time-based: SSID activity
        if ssid not in [None, "", "<hidden>"]:
            ssid_activity.setdefault(ssid, []).append(timestamp)

        # Time-based: AP load over time
        if bssid in ap_client_map:
            count = len(ap_client_map[bssid]["Clients"])
            ap_load_timeline.setdefault(bssid, []).append((timestamp, count))

        # RSSI timeline per client
        if src:
            client_rssi.setdefault(src, []).append((timestamp, rssi))

        records.append({
            "Source": src,
            "SourceVendor": lookup_vendor(src, OUI_DB),
            "Destination": dst,
            "DestinationVendor": lookup_vendor(dst, OUI_DB),
            "BSSID": bssid,
            "SSID": ssid,
            "Type": frame_type,
            "Subtype": frame_subtype,
            "Randomized": is_randomized_mac(src),
            "Timestamp": timestamp,
            "RSSI": rssi,
            "Channel": channel,
            "FrequencyMHz": freq_mhz,
            "Band": frequency_to_band(freq_mhz),
        })

    if args.limit is not None and processed_packets >= args.limit:
        break

print(f"\nTotal processed packets (after filters and limit): {processed_packets:,}")

print("\nBuilding DataFrame...")
df = pd.DataFrame(records)

# Replace hidden SSIDs with revealed ones when possible
for ap_mac, hidden in hidden_ssids.items():
    if ap_mac in revealed_ssids:
        df.loc[df["BSSID"] == ap_mac, "SSID"] = revealed_ssids[ap_mac]

# Group by SSID for later printing
grouped = df.groupby("SSID")

# Build SSID → BSSID map for wardrive table and anomalies
ssid_to_bssids = {}
for ap, info in ap_client_map.items():
    ssid = info.get("SSID")
    if ssid not in [None, "", "<hidden>"]:
        ssid_to_bssids.setdefault(ssid, set()).add(ap)




# ----------------- ANOMALY DETECTION ENGINE -----------------

anomalies = []

if not args.wardrive:
    print("Running anomaly detection...")

    # 1. Rogue AP detection
    for ap, info in ap_client_map.items():
        ssid = info["SSID"]
        clients = info["Clients"]
        vendor = lookup_vendor(ap, OUI_DB)

        if vendor == "Unknown Vendor" and len(clients) == 0:
            anomalies.append(
                f"Rogue AP suspected: {ap} broadcasting SSID={ssid} with unknown vendor and no clients"
            )

    # 2. Evil twin / SSID spoofing detection
    ssid_to_bssids = {}
    for ap, info in ap_client_map.items():
        ssid = info["SSID"]
        if ssid not in [None, "", "<hidden>"]:
            ssid_to_bssids.setdefault(ssid, set()).add(ap)

    for ssid, bssids in ssid_to_bssids.items():
        if len(bssids) > 1:
            vendors = {lookup_vendor(b, OUI_DB) for b in bssids}
            if len(vendors) > 1:
                anomalies.append(
                    f"Evil Twin suspected: SSID={ssid} broadcast by multiple vendors: {sorted(bssids)}"
                )

    # 3. Probe burst detection
    probe_times = {}  # client → list of timestamps
    probe_reqs = df[(df["Type"] == 0) & (df["Subtype"] == 4)]  # management, ProbeReq
    for _, row in probe_reqs.iterrows():
        probe_times.setdefault(row["Source"], []).append(row["Timestamp"])

    for client, times in probe_times.items():
        times.sort()
        for i in range(len(times) - 5):
            if times[i+5] - times[i] < 1.0:
                anomalies.append(
                    f"Probe burst: {client} sent 6+ probe requests in under 1 second"
                )
                break

    # 4. Suspicious roaming (too many roams in short time)
    for client, events in roaming_events.items():
        events_sorted = sorted(events, key=lambda x: x[3])
        for i in range(len(events_sorted) - 3):
            if events_sorted[i+3][3] - events_sorted[i][3] < 10:
                anomalies.append(
                    f"Suspicious roaming: {client} roamed 4+ times in under 10 seconds"
                )
                break

    # 5. Randomized MAC abuse
    randomized_macs = df[df["Randomized"] == True]["Source"].dropna().unique()
    for mac in randomized_macs:
        client_rows = df[df["Source"] == mac]
        if any(client_rows["Type"] == 2):
            anomalies.append(
                f"Randomized MAC {mac} sent data frames (unusual behavior)"
            )
        if mac in roaming_events:
            anomalies.append(
                f"Randomized MAC {mac} performed roaming (very unusual)"
            )

    # 6. AP load spikes
    for ap, entries in ap_load_timeline.items():
        entries_sorted = sorted(entries, key=lambda x: x[0])
        for i in range(len(entries_sorted) - 1):
            t1, c1 = entries_sorted[i]
            t2, c2 = entries_sorted[i+1]
            if c1 > 0 and c2 / max(c1, 1) > 3 and (t2 - t1) < 2:
                anomalies.append(
                    f"AP Load Spike: {ap} jumped from {c1} to {c2} clients in under 2 seconds"
                )
                break

    # 7. Deauthentication attack detection (subtype 12)
    deauth_frames = df[(df["Type"] == 0) & (df["Subtype"] == 12)]
    if not deauth_frames.empty:
        if len(deauth_frames) > 50:
            anomalies.append(
                f"Possible deauthentication attack: {len(deauth_frames)} deauth frames observed"
            )

        for src_mac, group in deauth_frames.groupby("Source"):
            times = sorted(group["Timestamp"])
            for i in range(len(times) - 9):
                if times[i+9] - times[i] < 5:
                    anomalies.append(
                        f"Deauth flood suspected from {src_mac}: 10+ deauth frames in under 5 seconds"
                    )
                    break

    # 8. Disassociation attack detection (subtype 10)
    disassoc_frames = df[(df["Type"] == 0) & (df["Subtype"] == 10)]
    if not disassoc_frames.empty:
        if len(disassoc_frames) > 50:
            anomalies.append(
                f"Possible disassociation attack: {len(disassoc_frames)} disassociation frames observed"
            )

        for src_mac, group in disassoc_frames.groupby("Source"):
            times = sorted(group["Timestamp"])
            for i in range(len(times) - 9):
                if times[i+9] - times[i] < 5:
                    anomalies.append(
                        f"Disassociation flood suspected from {src_mac}: 10+ disassociation frames in under 5 seconds"
                    )
                    break

    # 9. RSSI-based anomalies
    for client, samples in client_rssi.items():
        samples_sorted = sorted(samples, key=lambda x: x[0])
        for i in range(len(samples_sorted) - 1):
            t1, r1 = samples_sorted[i]
            t2, r2 = samples_sorted[i+1]
            if r1 is not None and r2 is not None:
                if abs(r2 - r1) > 25 and (t2 - t1) < 2:
                    anomalies.append(
                        f"RSSI anomaly: {client} signal changed by {abs(r2 - r1)} dB in under 2 seconds"
                    )
                    break

if not args.wardrive:
    print("Generating per-client session reports...")
    # all your per-client session report logic here
else:
    pass


# ----------------- WARDIVING TABLE BUILD -----------------


def build_wardriving_table(df, ap_client_map, OUI_DB):
    """
    Build a compact wardriving-style table summarizing all observed APs.
    Returns a list of formatted text lines.
    """

    table_lines = []
    table_lines.append("=== Wardriving Summary ===\n")

    # Table header
    header = (
        f"{'SSID':<18} {'BSSID':<18} {'CH':<4} {'BAND':<6} "
        f"{'RSSI':<6} {'CLIENTS':<8} {'VENDOR':<14} NOTES"
    )
    table_lines.append(header)
    table_lines.append("-" * len(header))

    # Build AP entries
    ap_entries = []

    for ap_mac, info in ap_client_map.items():
        ssid = info.get("SSID", "<unknown>")
        clients = info.get("Clients", set())
        client_count = len(clients)

        # Determine channel (mode of observed frames)
        ap_df = df[df["BSSID"] == ap_mac]
        if not ap_df.empty:
            channel_series = ap_df["Channel"].dropna()
            channel = int(channel_series.mode().iloc[0]) if not channel_series.empty else None

            band_series = ap_df["Band"].dropna()
            band = band_series.mode().iloc[0] if not band_series.empty else "Unknown"

            # Strongest RSSI observed for this AP
            rssi_series = ap_df["RSSI"].dropna()
            strongest_rssi = int(rssi_series.max()) if not rssi_series.empty else None
        else:
            channel = None
            band = "Unknown"
            strongest_rssi = None

        vendor = lookup_vendor(ap_mac, OUI_DB)

        # Build NOTES column
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

        # Randomized clients
        if any(is_randomized_mac(c) for c in clients):
            notes.append("Randomized clients")

        # Multi-BSSID SSID (possible evil twin)
        if ssid and ssid != "<hidden>":
            if ssid in ssid_to_bssids and len(ssid_to_bssids[ssid]) > 1:
                notes.append("Multi-BSSID")

        note_text = ", ".join(notes) if notes else ""

        ap_entries.append({
            "ssid": ssid,
            "bssid": ap_mac,
            "channel": channel,
            "band": band,
            "rssi": strongest_rssi,
            "clients": client_count,
            "vendor": vendor,
            "notes": note_text
        })

    # Sort by strongest RSSI (descending)
    ap_entries.sort(key=lambda x: (x["rssi"] is not None, x["rssi"]), reverse=True)

    # Format rows
    for ap in ap_entries:
        ssid_str = ap['ssid'] if ap['ssid'] not in [None, ""] else "<unknown>"
        bssid_str = ap['bssid'] if ap['bssid'] is not None else "-"
        channel_str = str(ap['channel']) if ap['channel'] is not None else "-"
        band_str = ap['band'] if ap['band'] is not None else "Unknown"
        rssi_str = str(ap['rssi']) if ap['rssi'] is not None else "-"
        vendor_str = ap['vendor'] if ap['vendor'] is not None else "Unknown"
        notes_str = ap['notes'] if ap['notes'] else ""

        table_lines.append(
            f"{ssid_str:<18} {bssid_str:<18} "
            f"{channel_str:<4} {band_str:<6} "
            f"{rssi_str:<6} {ap['clients']:<8} "
            f"{vendor_str:<14} {notes_str}"
        )

    return table_lines

def build_wardrive_csv(df, ap_client_map, OUI_DB, ssid_to_bssids):
    """
    Build a DataFrame for the wardriving table CSV export.
    Mirrors the logic of build_wardriving_table().
    """

    rows = []

    for ap_mac, info in ap_client_map.items():
        ssid = info.get("SSID", "<unknown>")
        clients = info.get("Clients", set())
        client_count = len(clients)

        # Determine channel, band, RSSI
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

        vendor = lookup_vendor(ap_mac, OUI_DB)

        # Notes
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

        rows.append({
            "SSID": ssid,
            "BSSID": ap_mac,
            "Channel": channel,
            "Band": band,
            "RSSI": strongest_rssi,
            "Clients": client_count,
            "Vendor": vendor,
            "Notes": ", ".join(notes)
        })

    return pd.DataFrame(rows)


# ----------------- SUMMARY BUILD -----------------

summary_lines = []

# --- WARDIVE MODE: Only output the wardriving table ---
if args.wardrive:
    summary_lines.extend(build_wardriving_table(df, ap_client_map, OUI_DB))

# --- FULL SUMMARY MODE (default) ---
else:
    # Always show wardrive table at the top
    summary_lines.extend(build_wardriving_table(df, ap_client_map, OUI_DB))

    # Main summary header
    summary_lines.append("=== Wireless Capture Summary ===")
    summary_lines.append(f"Total Frames: {len(df)}")
    summary_lines.append(f"Unique SSIDs: {df['SSID'].nunique()}")

    # Hidden SSIDs
    summary_lines.append("\nHidden SSIDs Revealed:")
    if revealed_ssids:
        for ap_mac, ssid in sorted(revealed_ssids.items(), key=lambda x: x[1].lower()):
            summary_lines.append(f"  {ap_mac} → {ssid}")
    else:
        summary_lines.append("  None detected")

    # Randomized MACs
    summary_lines.append("\nRandomized MAC Addresses:")
    if len(randomized_macs) > 0:
        for mac in sorted(randomized_macs):
            summary_lines.append(f"  {mac}")
    else:
        summary_lines.append("  None detected")

    # Randomized MAC → AP/SSID associations
    summary_lines.append("\nRandomized MAC Associations:")
    if randomized_associations:
        for mac, targets in sorted(randomized_associations.items()):
            summary_lines.append(f"  {mac}:")
            for ssid, bssid in sorted(targets, key=lambda x: (x[0] or "", x[1] or "")):
                summary_lines.append(f"      SSID={ssid}, BSSID={bssid}")
    else:
        summary_lines.append("  None detected")

    # AP–Client associations
    summary_lines.append("\nAP–Client Associations:")
    if ap_client_map:
        for ap_mac, info in sorted(ap_client_map.items()):
            ssid = info["SSID"]
            clients = info["Clients"]

            ap_band_series = df[df["BSSID"] == ap_mac]["Band"].mode()
            ap_band = ap_band_series.iloc[0] if not ap_band_series.empty else "Unknown"

            summary_lines.append(f"  AP {ap_mac} (SSID={ssid}, Band={ap_band}):")
            for client in sorted(clients):
                vendor = lookup_vendor(client, OUI_DB)
                summary_lines.append(f"      {client} ({vendor})")
    else:
        summary_lines.append("  None detected")

    # Roaming events
    summary_lines.append("\nRoaming Events:")
    if roaming_events:
        for client, events in sorted(roaming_events.items()):
            summary_lines.append(f"  Client {client}:")
            for old_ap, new_ap, ssid, ts in sorted(events, key=lambda x: x[3]):
                new_band_series = df[df["BSSID"] == new_ap]["Band"].mode()
                new_band = new_band_series.iloc[0] if not new_band_series.empty else "Unknown"
                summary_lines.append(
                    f"      {ts:.2f} — {old_ap} → {new_ap} (SSID={ssid}, Band={new_band})"
                )
    else:
        summary_lines.append("  None detected")

    # Client timelines
    summary_lines.append("\nClient Timelines:")
    for client in sorted(client_first_seen.keys()):
        first = client_first_seen[client]
        last = client_last_seen[client]
        duration = last - first

        client_band_series = df[df["Source"] == client]["Band"].mode()
        client_band = client_band_series.iloc[0] if not client_band_series.empty else "Unknown"

        summary_lines.append(
            f"  {client}: first={first:.2f}, last={last:.2f}, duration={duration:.2f}s, Band={client_band}"
        )

    # SSID activity windows
    summary_lines.append("\nSSID Activity Windows:")
    for ssid, times in sorted(ssid_activity.items()):
        first = min(times)
        last = max(times)

        ssid_band_series = df[df["SSID"] == ssid]["Band"].mode()
        ssid_band = ssid_band_series.iloc[0] if not ssid_band_series.empty else "Unknown"

        summary_lines.append(
            f"  {ssid}: {first:.2f} → {last:.2f} ({len(times)} frames, Band={ssid_band})"
        )

    # AP load over time
    summary_lines.append("\nAP Load Over Time:")
    if ap_load_timeline:
        for ap, entries in sorted(ap_load_timeline.items()):
            ssid = ap_client_map.get(ap, {}).get("SSID", "Unknown")

            ap_band_series = df[df["BSSID"] == ap]["Band"].mode()
            ap_band = ap_band_series.iloc[0] if not ap_band_series.empty else "Unknown"

            summary_lines.append(f"  AP {ap} (SSID={ssid}, Band={ap_band}):")
            for ts, count in entries:
                summary_lines.append(f"      {ts:.2f} — {count} clients")
    else:
        summary_lines.append("  None tracked")

    # RSSI summary
    summary_lines.append("\nRSSI Summary:")
    if client_rssi:
        for client, samples in sorted(client_rssi.items()):
            values = [v for (_, v) in samples if v is not None]
            client_band_series = df[df["Source"] == client]["Band"].mode()
            client_band = client_band_series.iloc[0] if not client_band_series.empty else "Unknown"

            if values:
                strongest = max(values)
                weakest = min(values)
                avg = sum(values) / len(values)
                summary_lines.append(
                    f"  {client}: strongest={strongest} dBm, weakest={weakest} dBm, avg={avg:.1f} dBm, Band={client_band}"
                )
            else:
                summary_lines.append(f"  {client}: No RSSI data available, Band={client_band}")
    else:
        summary_lines.append("  No RSSI data collected")

    # Observed frequency bands
    summary_lines.append("\nObserved Frequency Bands:")
    summary_lines.append(f"  2.4 GHz: {'Yes' if observed_bands['2.4GHz'] else 'No'}")
    summary_lines.append(f"  5 GHz:   {'Yes' if observed_bands['5GHz'] else 'No'}")
    summary_lines.append(f"  6 GHz:   {'Yes' if observed_bands['6GHz'] else 'No'}")

    # Anomalies
    summary_lines.append("\nAnomalies Detected:")
    if anomalies:
        for a in sorted(anomalies):
            summary_lines.append(f"  - {a}")
    else:
        summary_lines.append("  None detected")

    # Frames per SSID
    summary_lines.append("\nFrames Per SSID:")
    ssid_counts = df.groupby("SSID").size().reset_index(name="Frames")
    for _, row in ssid_counts.iterrows():
        summary_lines.append(f"  {row['SSID']}: {row['Frames']}")

    summary_lines.append("\n================================\n")

# ----------------- PER-CLIENT SESSION REPORTS -----------------
session_lines = []

if not args.wardrive:

    session_lines.append("=== Client Session Reports ===")

    all_clients = sorted(client_first_seen.keys())

    for client in all_clients:
        vendor = lookup_vendor(client, OUI_DB)
        first = client_first_seen.get(client)
        last = client_last_seen.get(client)
        duration = (last - first) if (first is not None and last is not None) else None
        is_randomized = client in randomized_macs

        client_band_series = df[df["Source"] == client]["Band"].mode()
        client_band = client_band_series.iloc[0] if not client_band_series.empty else "Unknown"

        session_lines.append(f"\n=== Client: {client} ({vendor}, Band={client_band}) ===")
        if first is not None:
            session_lines.append(f"First Seen: {first:.2f}")
        if last is not None:
            session_lines.append(f"Last Seen:  {last:.2f}")
        if duration is not None:
            session_lines.append(f"Duration:   {duration:.2f}s")
        session_lines.append(f"Randomized MAC: {'Yes' if is_randomized else 'No'}")

        # Probe activity
        session_lines.append("\nProbe Activity:")
        client_probes = df[(df["Type"] == 0) & (df["Subtype"] == 4) & (df["Source"] == client)]
        if not client_probes.empty:
            for _, row in client_probes.sort_values("Timestamp").iterrows():
                ts = row["Timestamp"]
                s = row["SSID"]
                band = row.get("Band", "Unknown")
                session_lines.append(f"  {ts:.2f} — Probed for \"{s}\" (Band={band})")
        else:
            session_lines.append("  None observed")

        # Associations
        session_lines.append("\nAssociations:")
        assoc_frames = df[
            (df["Type"] == 0) &
            (df["Subtype"].isin([0, 2])) &
            (df["Source"] == client)
        ]
        if not assoc_frames.empty:
            for _, row in assoc_frames.sort_values("Timestamp").iterrows():
                ts = row["Timestamp"]
                ap = row["BSSID"]
                s = row["SSID"]
                band = row.get("Band", "Unknown")
                session_lines.append(
                    f"  {ts:.2f} — Associated to AP {ap} (SSID={s}, Band={band})"
                )
        else:
            session_lines.append("  None observed")

        # Roaming events (tag by new AP band)
        session_lines.append("\nRoaming:")
        if client in roaming_events:
            events_sorted = sorted(roaming_events[client], key=lambda x: x[3])
            for old_ap, new_ap, s, ts in events_sorted:
                new_band_series = df[df["BSSID"] == new_ap]["Band"].mode()
                new_band = new_band_series.iloc[0] if not new_band_series.empty else "Unknown"
                session_lines.append(
                    f"  {ts:.2f} — {old_ap} → {new_ap} (SSID={s}, Band={new_band})"
                )
        else:
            session_lines.append("  None observed")

        # RSSI stats (client-level band already included in header)
        session_lines.append("\nRSSI Stats:")
        samples = client_rssi.get(client, [])
        values = [v for (_, v) in samples if v is not None]
        if values:
            strongest = max(values)
            weakest = min(values)
            avg = sum(values) / len(values)
            session_lines.append(
                f"  Strongest: {strongest} dBm, Weakest: {weakest} dBm, Avg: {avg:.1f} dBm"
            )
        else:
            session_lines.append("  No RSSI data available")

        # Client-specific anomalies with band tagging
        session_lines.append("\nAnomalies:")
        client_anoms = [a for a in anomalies if client in a]
        if client_anoms:
            for a in client_anoms:
                band_series = df[df["Source"] == client]["Band"].mode()
                band = band_series.iloc[0] if not band_series.empty else "Unknown"
                session_lines.append(f"  - {a} (Band={band})")
        else:
            session_lines.append("  None recorded")
else:
    pass


session_lines.append("\n================================\n")

# ----------------- CSV DATA STRUCTURES -----------------

# Skip CSV generation entirely if "--no-csv" is used
if not args.no_csv and not args.wardrive:
    print("    Building CSV data structures. This may take a while...")


    # 1. Per-client summary
    print("    Building Per-Client Summary CSV...")
    client_rows = []
    for client in sorted(client_first_seen.keys()):
        first = client_first_seen.get(client)
        last = client_last_seen.get(client)
        duration = (last - first) if (first is not None and last is not None) else None
        vendor = lookup_vendor(client, OUI_DB)
        is_rand = client in randomized_macs

        samples = client_rssi.get(client, [])
        rssi_values = [v for (_, v) in samples if v is not None]
        strongest = max(rssi_values) if rssi_values else None
        weakest = min(rssi_values) if rssi_values else None
        avg_rssi = (sum(rssi_values) / len(rssi_values)) if rssi_values else None

        client_band_series = df[df["Source"] == client]["Band"].mode()
        client_band = client_band_series.iloc[0] if not client_band_series.empty else "Unknown"

        probe_count = len(probe_times.get(client, []))
        assoc_frames_client = df[
            (df["Type"] == 0) &
            (df["Subtype"].isin([0, 2])) &
            (df["Source"] == client)
        ]
        assoc_count = len(assoc_frames_client)
        roam_count = len(roaming_events.get(client, []))
        anomaly_count = sum(1 for a in anomalies if client in a)

        client_rows.append({
            "ClientMAC": client,
            "Vendor": vendor,
            "FirstSeen": first,
            "LastSeen": last,
            "DurationSeconds": duration,
            "RandomizedMAC": is_rand,
            "ProbeCount": probe_count,
            "AssociationCount": assoc_count,
            "RoamCount": roam_count,
            "AnomalyCount": anomaly_count,
            "RSSI_Strongest": strongest,
            "RSSI_Weakest": weakest,
            "RSSI_Average": avg_rssi,
            "DominantBand": client_band,
        })

    clients_df = pd.DataFrame(client_rows)

    # 2. AP summary
    print("    Building AP summary CSV...")
    ap_rows = []
    for ap, info in ap_client_map.items():
        ssid = info["SSID"]
        clients = info["Clients"]
        vendor = lookup_vendor(ap, OUI_DB)

        ap_band_series = df[df["BSSID"] == ap]["Band"].mode()
        ap_band = ap_band_series.iloc[0] if not ap_band_series.empty else "Unknown"

        ap_rows.append({
            "AP_BSSID": ap,
            "SSID": ssid,
            "Vendor": vendor,
            "ClientCount": len(clients),
            "DominantBand": ap_band,
        })

    aps_df = pd.DataFrame(ap_rows)

    # 3. Anomalies
    print("    Building Anomalies CSV...")
    anoms_df = pd.DataFrame([{"Description": a} for a in anomalies])

    print("    Building Roaming Events CSV...")
    # 4. Roaming events
    roam_rows = []
    for client, events in roaming_events.items():
        for old_ap, new_ap, ssid, ts in events:
            new_band_series = df[df["BSSID"] == new_ap]["Band"].mode()
            new_band = new_band_series.iloc[0] if not new_band_series.empty else "Unknown"
            roam_rows.append({
                "ClientMAC": client,
                "OldAP": old_ap,
                "NewAP": new_ap,
                "SSID": ssid,
                "Timestamp": ts,
                "Band": new_band,
            })

    roaming_df = pd.DataFrame(roam_rows)

    # 5. RSSI timeline (vectorized + EDecimal-safe)
    rssi_rows = []

    # Flatten client_rssi dict into a list of rows
    for client, samples in client_rssi.items():
        for ts, rssi in samples:
            # Convert timestamp to float for merge compatibility
            rssi_rows.append({
                "ClientMAC": client,
                "Timestamp": float(ts),
                "RSSI": rssi,
            })

    # If no RSSI samples exist, create empty DataFrame
    if not rssi_rows:
        rssi_df = pd.DataFrame(columns=["ClientMAC", "Timestamp", "RSSI", "Band"])
    else:
        # Build base RSSI DataFrame
        rssi_df = pd.DataFrame(rssi_rows)

        # Prepare df slice for merging (convert Timestamp to float)
        band_df = df[["Source", "Timestamp", "Band"]].copy()
        band_df["Timestamp"] = band_df["Timestamp"].astype(float)
        band_df = band_df.rename(columns={"Source": "ClientMAC"})

        # Merge to attach Band info
        rssi_df = rssi_df.merge(
            band_df,
            on=["ClientMAC", "Timestamp"],
            how="left"
        )

        # Fill missing Band values
        rssi_df["Band"] = rssi_df["Band"].fillna("Unknown")

    # 6. SSID activity windows
    print("    Building SSID activity CSV...")
    ssid_rows = []
    for ssid, times in ssid_activity.items():
        if not times:
            continue
        first = min(times)
        last = max(times)
        ssid_band_series = df[df["SSID"] == ssid]["Band"].mode()
        ssid_band = ssid_band_series.iloc[0] if not ssid_band_series.empty else "Unknown"
        ssid_rows.append({
            "SSID": ssid,
            "FirstSeen": first,
            "LastSeen": last,
            "FrameCount": len(times),
            "DominantBand": ssid_band,
        })

    ssid_df = pd.DataFrame(ssid_rows)

    # 7. AP load timeline
    print("    Building AP load timeline CSV...")
    ap_load_rows = []
    for ap, entries in ap_load_timeline.items():
        ap_band_series = df[df["BSSID"] == ap]["Band"].mode()
        ap_band = ap_band_series.iloc[0] if not ap_band_series.empty else "Unknown"
        for ts, count in entries:
            ap_load_rows.append({
                "AP_BSSID": ap,
                "Timestamp": ts,
                "ClientCount": count,
                "Band": ap_band,
            })

    ap_load_df = pd.DataFrame(ap_load_rows)

    # 8. Randomized MAC associations
    print("    Building Randomized MAC associations CSV...")
    rand_assoc_rows = []
    for mac, targets in randomized_associations.items():
        for ssid, bssid in targets:
            band_series = df[(df["Source"] == mac) & (df["BSSID"] == bssid)]["Band"]
            band = band_series.iloc[0] if not band_series.empty else "Unknown"
            rand_assoc_rows.append({
                "RandomizedMAC": mac,
                "SSID": ssid,
                "BSSID": bssid,
                "Band": band,
            })

    rand_assoc_df = pd.DataFrame(rand_assoc_rows)

    print("CSV data structures built.")

else:
    if args.no_csv:
        print("CSV data structures skipped (--no-csv enabled)")
    elif args.wardrive:
        print("CSV data structures skipped (wardrive mode)")


# ----------------- WRITE TXT OUTPUT -----------------

txt_path = os.path.join(args.out, "wireless_summary.txt")

if not args.no_txt:
    print("Writing TXT summary...")

    with open(txt_path, "w") as f:

        # Always write the summary_lines (wardrive table is already included if needed)
        for line in summary_lines:
            f.write(line + "\n")

        # --- WARDIVE MODE: ONLY wardrive table, nothing else ---
        if args.wardrive:
            # Do NOT write session reports or SSID tables
            pass

        # --- SUMMARY-ONLY MODE: summary without session reports or SSID tables ---
        elif args.summary_only:
            f.write("\n=== Light TXT Mode Enabled ===\n")
            f.write("Session reports and per-SSID raw tables were skipped.\n")
            f.write("Use --summary-only to toggle this behavior.\n")

        # --- FULL MODE: write everything ---
        else:
            # Write per-client session reports
            for line in session_lines:
                f.write(line + "\n")

            # Write per-SSID raw frame tables
            for ssid, group in grouped:
                f.write(f"\n=== SSID: {ssid} ===\n")
                f.write(group.to_string(index=False))
                f.write("\n")

    print(f"    TXT output saved to {txt_path}")

else:
    print("TXT export skipped (--no-txt enabled)")


# ----------------- WRITE CSV OUTPUTS -----------------

if not args.no_csv:
    print("Writing CSV exports...")

    if should_export("frames"):
        df.to_csv(os.path.join(args.out, "frames.csv"), index=False)
    if should_export("clients"):
        clients_df.to_csv(os.path.join(args.out, "clients.csv"), index=False)
    if should_export("aps"):
        aps_df.to_csv(os.path.join(args.out, "aps.csv"), index=False)
    if should_export("anomalies"):
        anoms_df.to_csv(os.path.join(args.out, "anomalies.csv"), index=False)
    if should_export("roaming"):
        roaming_df.to_csv(os.path.join(args.out, "roaming.csv"), index=False)
    if should_export("rssi_timeline"):
        rssi_df.to_csv(os.path.join(args.out, "rssi_timeline.csv"), index=False)
    if should_export("ssid_activity"):
        ssid_df.to_csv(os.path.join(args.out, "ssid_activity.csv"), index=False)
    if should_export("ap_load_timeline"):
        ap_load_df.to_csv(os.path.join(args.out, "ap_load_timeline.csv"), index=False)
    if should_export("randomized_associations"):
        rand_assoc_df.to_csv(os.path.join(args.out, "randomized_associations.csv"), index=False)
    if should_export("wardrive") and not args.no_csv:
        print("Writing wardrive.csv...")
        wardrive_df = build_wardrive_csv(df, ap_client_map, OUI_DB, ssid_to_bssids)
        wardrive_df.to_csv(os.path.join(args.out, "wardrive.csv"), index=False)
    if should_export("frequencies"):
        df[["Timestamp", "Source", "BSSID", "Channel", "FrequencyMHz", "Band"]].to_csv(
            os.path.join(args.out, "frequencies.csv"), index=False
        )

    print("    CSV exports complete.")

else:
    print("CSV export skipped (--no-csv enabled)")

print("\nDone!")