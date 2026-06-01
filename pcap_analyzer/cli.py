# ================================================================
#  cli.py
#  Command-line argument parsing
# ================================================================

import argparse
import sys

VERSION = "1.0.0"

# All available CSV export names and their descriptions.
# Imported by other modules that need to validate or display CSV names.
CSV_DESCRIPTIONS = {
    "frames":                  "All captured frames with metadata",
    "clients":                 "Per-client summary (first/last seen, RSSI stats)",
    "aps":                     "Access point summary (SSID, vendor, client count)",
    "anomalies":               "High-level anomaly descriptions",
    "roaming":                 "Roaming events with timestamps",
    "rssi_timeline":           "Per-client RSSI timeline (timestamp → RSSI)",
    "ssid_activity":           "SSID activity windows and frame counts",
    "ap_load_timeline":        "AP client load over time",
    "randomized_associations": "Randomized MAC → SSID/BSSID associations",
    "frequencies":             "Per-frame channel, frequency, and band",
    "wardrive":                "Wardriving table (SSID, BSSID, channel, band, RSSI, clients, vendor, notes)",
    "auth_failures":           "Authentication failures per AP with status codes and descriptions",
    "assoc_failures":          "Association failures per AP with status codes and descriptions",
    "deauth_events":           "All deauthentication events with reason codes",
    "disassoc_events":         "All disassociation events with reason codes",
    "client_event_timeline":   "Per-client chronological log of auth/assoc/deauth/disassoc events",
    "dhcp_events":             "Every DHCP message with timestamp, client, type, and offered IP",
    "dhcp_sessions":           "Full DHCP session lifecycle per transaction (DISCOVER through ACK/NAK)",
}

VALID_CSVS = set(CSV_DESCRIPTIONS.keys())


def parse_args():
    """
    Build and parse the CLI argument parser.
    Handles the '?' help shortcut, --list-csv, and --help-filters early exits.
    Returns the parsed args namespace.
    """

    # Allow '?' as an alias for '-h'
    if len(sys.argv) == 2 and sys.argv[1] == "?":
        sys.argv[1] = "-h"

    parser = argparse.ArgumentParser(
        prog="pcap_analyzer.py",
        description=(
            "Wireless PCAP Analyzer\n"
            "Analyze Wi-Fi PCAP files and export structured TXT and CSV reports.\n\n"
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
        help="Output only the wardriving table (no full summary)",
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

    # --- Early exits for informational flags ---

    if args.help_filters:
        _print_filter_help()
        raise SystemExit(0)

    if args.list_csv:
        _print_csv_list()
        raise SystemExit(0)

    # --pcap is required for all real work
    if not args.pcap:
        raise SystemExit('Error: --pcap is required unless "?", -h, --list-csv or --help-filters is used.')

    # --- Resolve the set of requested CSVs ---
    if args.csv_list:
        requested_csvs = {name.strip().lower() for name in args.csv_list.split(",")}
    else:
        requested_csvs = None  # None means "export all"

    if args.wardrive:
        requested_csvs = {"wardrive"}

    # Validate CSV names if a specific list was provided
    if requested_csvs is not None:
        unknown = requested_csvs - VALID_CSVS
        if unknown:
            print("Error: The following CSV names are not recognized:")
            for name in sorted(unknown):
                print(f"  - {name}")
            print("\nValid CSV names are:")
            print("  " + ", ".join(sorted(VALID_CSVS)))
            print("\nPlease correct the CSV names and try again.")
            raise SystemExit(1)

    # Attach the resolved set back onto args so the rest of the program can use it
    args.requested_csvs = requested_csvs

    return args


def _print_filter_help():
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


def _print_csv_list():
    print("Available CSV exports:\n")
    for name in sorted(VALID_CSVS):
        desc = CSV_DESCRIPTIONS.get(name, "")
        print(f"  {name:<22} {desc}")
