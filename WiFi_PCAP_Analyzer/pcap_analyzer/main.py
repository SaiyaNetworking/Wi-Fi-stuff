# ================================================================
#  main.py
#  Program orchestrator.
#  Calls each module in sequence — no business logic lives here.
# ================================================================

import glob
import os

from .cli import parse_args
from .oui import load_oui_database
from .processor import process_packets
from .anomalies import detect_anomalies
from .reports.txt import write_txt_report
from .reports.csv_export import export_all_csvs
from .reports.wardrive import build_wardriving_table, build_wardrive_csv


def main():
    # 1. Parse CLI arguments
    args = parse_args()

    # 2. Expand PCAP file paths (files, wildcards, directories)
    pcaps = _resolve_pcaps(args.pcap)

    # 3. Ensure output directory exists
    os.makedirs(args.out, exist_ok=True)

    # 4. Load the OUI vendor database
    oui_db = load_oui_database("oui.txt")

    # 5. Process all PCAP files → PcapResult
    result = process_packets(pcaps, args, oui_db)

    # 6. Anomaly detection (skipped in wardrive mode)
    if not args.wardrive:
        print("Running anomaly detection...")
        anomalies = detect_anomalies(result, oui_db)
    else:
        anomalies = []

    # 7. Write TXT report
    if not args.no_txt:
        write_txt_report(result, anomalies, oui_db, args)
    else:
        print("TXT export skipped (--no-txt enabled)")

    # 8. Write CSV exports
    if not args.no_csv:
        if args.wardrive:
            # Wardrive mode: only the wardrive CSV
            import os as _os
            wardrive_df = build_wardrive_csv(result, oui_db)
            wardrive_df.to_csv(_os.path.join(args.out, "wardrive.csv"), index=False)
            print("    Wrote wardrive.csv")
        else:
            export_all_csvs(result, anomalies, oui_db, args)
    else:
        print("CSV export skipped (--no-csv enabled)")

    print("\nDone!")


# ----------------------------------------------------------------
# Helper
# ----------------------------------------------------------------

def _resolve_pcaps(pcap_args):
    """Expand --pcap arguments into a concrete list of .pcap file paths."""
    pcaps = []
    for item in pcap_args:
        if os.path.isdir(item):
            pcaps.extend(glob.glob(os.path.join(item, "*.pcap")))
        else:
            pcaps.extend(glob.glob(item))

    if not pcaps:
        raise SystemExit("No PCAP files found for the given --pcap argument(s).")

    return pcaps
