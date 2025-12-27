# Wireless PCAP Analyzer
A beginner‑friendly Wi‑Fi recon analysis toolkit. This was specifically built to parse pcaps from the Hak5 Pineapple Pager's Recon Mode but can be used for other wireless pcap captures.


The Wireless PCAP Analyzer is a command‑line tool that processes 802.11 PCAP files and generates parsed TXT and CSV reports. This is intended to be a more streamlined, 
faster analysis tool than sifting through wireshark or uploading pcaps into someone else's program. This is an open source program that is meant for you and you alone.

This is more tailored for students, hobbyists, and analysts who want to understand Wi‑Fi activity while wardriving and dissecting Wi-Fi data around them.
This script uses Scapy for packet parsing and Pandas for data analysis.

*NOTE: These readings are approximated to the capabilities of your monitoring device(s) and the ability of the program to parse the pcap information. Not everything will be 100% accurate but rather will give a general understand of your surroundings.*

## Features
- A dedicated wardriving table for:
  - SSID + associated BSSID
  - Channel + band
  - Approximate RSSI
  - Approximate client count
  - Vendor lookup
  - Cursory notes on strength, randomzied clients, multi-BSSID
- Detect hidden SSIDs and reveal them when possible
- Identify randomized MAC addresses and their associations
- Map AP–Client relationships with vendor lookup
- Detect and flag roaming events, probe bursts, evil twins, and other anomalies
- Extract RSSI, channels, frequencies, and band usage (2.4 / 5 / 6 GHz)
- Will generate:
    - Full TXT summary
    - Per‑client session reports
    - Per‑SSID raw frame tables
    - CSV exports for deeper analysis
    - A dedicated wardriving table (TXT + CSV)

## Requirements
- Python 3.8+ (recommend a .venv setup)
- Scapy
- Pandas
- A monitor‑mode Wi‑Fi capture (pcap)


## Quick Start
1. Install dependencies
`pip install scapy pandas`


2. Run the analyzer on a PCAP file
`python3 pcap_analyzer.py --pcap example.pcap --out directory`


This will generate:
- A directory named "directory" to insert the output files
- `wireless_summary.txt` - a text file with a full output of all datasets
- A set of CSV files (frames, clients, aps, anomalies, etc.)


### Understanding the Output
`wireless_summary.txt` produces a readable breakdown of:
- Wardriving table
- Hidden SSIDs
- Randomized MACs
- AP–Client associations
- Roaming events
- RSSI summaries
- SSID activity windows
- Anomalies
- Frames per SSID
Per‑client session reports
Shows:
- First/last seen
- Probe requests
- Associations
- Roaming
- RSSI stats
- Client‑specific anomalies
Per‑SSID raw tables
Every frame associated with each SSID — great for deep dives.

### Wardrive Mode (fast recons)
If you only want a wardriving‑style table:
`python3 pcap_analyzer.py --pcap example.pcap --wardrive`


This outputs:
- `wireless_summary.txt` (wardrive table only)
- `wardrive.csv`
Everything else is skipped for speed.

### Summary‑Only Mode
If you want a lightweight TXT summary without session reports or raw SSID tables:
`python3 pcap_analyzer.py --pcap example.pcap --summary-only`



### For large PCAP files (10k+ packet captures)
- `--no-csv` will omit the creation of CSV tables
- `--list-csv` will only create the specified CSV tables (anomalies, aps, roaming, etc...)
- `--limit 5000` will limit the analyzed packets to the first 5000 (5000 as an example)
- `--filter` will filter for a specific dataset (ssid, mac, type, subtype)


## Command-line interface commands:

### Input Options
 `--pcap example.pcap` — Specify one or more PCAP files, folders, or wildcards to analyze.  
 `--limit 1000` — Process only the first 1000 packets for faster previews. Change to any number value  
 `--filter [ssid/mac/type/subtype]` — Filter frames by ssid, mac, type, or subtype (repeatable).

### Output Options
 `--out example_directory` — Choose where TXT and CSV output files are saved (/example_directory as an example)   
 `--summary-only` — Generate a lightweight TXT summary without session reports or SSID tables.  
 `--wardrive` — Ultra‑fast mode that outputs only the wardriving table (TXT + CSV).  
 `--no-txt` — Skip generating the TXT summary file.  
 `--no-csv` — Skip generating all CSV files.

### CSV Control
 `--csv-list a,b,c` — Export only the specified CSV tables (e.g., frames, aps, roaming).  
 `--list-csv` — Print all available CSV export names and exit.

### General
 `--version` — Display the program version and exit.  
 `--help-filters` — Show examples and usage for the --filter argument.  
 `-h` — help. Lists out the usable arguments and flags  
 `?` — Shortcut for help; behaves the same as `-h`

## Sample usage

placeholder text.




## Q & A's
***Why not use wireshark?***    
Because I'm bad at wireshark and I wanted something that would aggregate information quickly    
on any linux environment. Termux on mobile is currently a work in progress.

***Was this written by AI?***    
Yes! Microsoft Copilot, specifically. It took about 60 hours and hundreds of prompts to build this.    
It might make a professional balk at the formatting but I think it's the coolest thing ever!

***Isn't this illegal?***    
Wardriving isn't illegal and I intentionally omitted any handshake analysis. Some basic OSINT did     
pull up a bunch of Wi-Fi passwords though. Whoopsie daisies, be sure to secure your networks.

***This is cool how do I hack my neighbor's/friend's/school's Wi-Fi?***    
I'm sure you could add some modules but this isn't the intended purpose of this program.    
There are better options like aircrack-ng or Fern WiFi Cracker. It's also illegal unless you have    
written consent from an authorized party.

***Is this really just a recon analysis tool?***    
It really is! I built this to help better understand the ubiquitous nature of Wi-Fi without having to    
be forced to pay for someone's program online and to have something local that anybody can use.    
I'm also not great at wireshark so this helps me quickly digest information in a simple .txt format.



