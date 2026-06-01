# ================================================================
#  dhcp_parser.py
#  DHCP message parsing and session tracking.
#  DHCP rides inside UDP/67-68 inside 802.11 data frames.
# ================================================================

from dataclasses import dataclass, field
from scapy.all import DHCP, BOOTP, IP


# DHCP message type codes (option 53)
DHCP_MSG_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}


@dataclass
class DHCPSession:
    """
    Tracks the full DHCP exchange for one client transaction.
    A complete healthy session flows: DISCOVER -> OFFER -> REQUEST -> ACK
    """
    client_mac:     str   = None
    transaction_id: int   = None
    discover_time:  float = None
    offer_time:     float = None
    offer_ip:       str   = None
    offer_server:   str   = None
    request_time:   float = None
    ack_time:       float = None
    nak_time:       float = None
    assigned_ip:    str   = None
    lease_time:     int   = None
    completed:      bool  = False
    failed:         bool  = False
    failure_reason: str   = None


def is_dhcp_packet(pkt):
    """Return True if this packet contains a DHCP message."""
    return pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)


def parse_dhcp_packet(pkt, timestamp, sessions, events):
    """
    Parse a single DHCP packet and update the session and event trackers.

    Parameters
    ----------
    pkt       : scapy packet (already confirmed to have DHCP layer)
    timestamp : packet timestamp
    sessions  : dict of transaction_id -> DHCPSession (mutated in place)
    events    : list of event dicts for the CSV export (mutated in place)
    """
    bootp = pkt[BOOTP]
    dhcp  = pkt[DHCP]

    xid = bootp.xid

    # chaddr is 16 bytes padded — take first 6 and format as MAC
    raw_chaddr = bootp.chaddr
    if isinstance(raw_chaddr, bytes):
        client_mac = ":".join(f"{b:02x}" for b in raw_chaddr[:6])
    else:
        client_mac = str(raw_chaddr)

    client_ip  = str(bootp.ciaddr) if bootp.ciaddr and str(bootp.ciaddr) != "0.0.0.0" else None
    your_ip    = str(bootp.yiaddr) if bootp.yiaddr and str(bootp.yiaddr) != "0.0.0.0" else None
    server_ip  = str(pkt[IP].src) if pkt.haslayer(IP) else None

    # Pull DHCP options
    msg_type_code = None
    lease_time    = None
    for opt in dhcp.options:
        if isinstance(opt, tuple):
            if opt[0] == "message-type":
                msg_type_code = opt[1]
            elif opt[0] == "lease_time":
                lease_time = opt[1]

    if msg_type_code is None:
        return

    msg_type = DHCP_MSG_TYPES.get(msg_type_code, f"UNKNOWN_{msg_type_code}")

    # Get or create the session for this transaction
    session = sessions.setdefault(xid, DHCPSession(
        client_mac=client_mac,
        transaction_id=xid,
    ))

    # Update session state
    if msg_type == "DISCOVER":
        session.discover_time = timestamp
        session.client_mac    = client_mac

    elif msg_type == "OFFER":
        session.offer_time   = timestamp
        session.offer_ip     = your_ip
        session.offer_server = server_ip

    elif msg_type == "REQUEST":
        session.request_time = timestamp

    elif msg_type == "ACK":
        session.ack_time    = timestamp
        session.assigned_ip = your_ip
        session.lease_time  = lease_time
        session.completed   = True

    elif msg_type == "NAK":
        session.nak_time       = timestamp
        session.failed         = True
        session.failure_reason = "Server sent NAK — client may be on wrong subnet"

    elif msg_type == "DECLINE":
        session.failed         = True
        session.failure_reason = "Client declined offer — possible IP conflict (DAD failure)"

    # Record every message as a flat event for the timeline CSV
    events.append({
        "Timestamp":     float(timestamp),
        "ClientMAC":     client_mac,
        "TransactionID": xid,
        "MessageType":   msg_type,
        "ClientIP":      client_ip,
        "OfferedIP":     your_ip,
        "ServerIP":      server_ip,
        "LeaseTime":     lease_time,
    })


def analyze_dhcp_sessions(sessions):
    """
    Inspect completed and incomplete DHCP sessions for anomalies.
    Returns a list of anomaly description strings.
    """
    anomalies = []

    # --- Starvation detection: one MAC with many transactions ---
    mac_session_counts = {}
    for session in sessions.values():
        mac = session.client_mac
        if mac:
            mac_session_counts[mac] = mac_session_counts.get(mac, 0) + 1

    for mac, count in mac_session_counts.items():
        if count > 50:
            anomalies.append(
                f"DHCP starvation suspected: {mac} initiated {count} "
                f"separate DHCP transactions"
            )

    # --- Rogue DHCP server: same IP offered by multiple servers ---
    ip_servers = {}
    for session in sessions.values():
        if session.offer_ip and session.offer_server:
            ip_servers.setdefault(session.offer_ip, set()).add(session.offer_server)
    for ip, servers in ip_servers.items():
        if len(servers) > 1:
            anomalies.append(
                f"Rogue DHCP server suspected: IP {ip} offered by "
                f"multiple servers: {sorted(servers)}"
            )

    # --- Per-session failure and timing checks ---
    for xid, session in sessions.items():
        mac = session.client_mac or f"xid={xid}"

        if session.failed:
            anomalies.append(
                f"DHCP failure for {mac} (xid={xid}): {session.failure_reason}"
            )

        elif not session.completed:
            if session.discover_time and not session.offer_time:
                anomalies.append(
                    f"DHCP: {mac} sent DISCOVER but received no OFFER "
                    f"— check VLAN config or DHCP scope exhaustion"
                )
            elif session.offer_time and not session.request_time:
                anomalies.append(
                    f"DHCP: {mac} received OFFER from {session.offer_server} "
                    f"but sent no REQUEST — possible IP conflict or client bug"
                )
            elif session.request_time and not session.ack_time:
                anomalies.append(
                    f"DHCP: {mac} sent REQUEST but received no ACK "
                    f"— server may be unreachable or scope exhausted"
                )

        # Very short leases cause repeated re-authentication
        if session.lease_time is not None and session.lease_time < 300:
            anomalies.append(
                f"DHCP: {mac} received lease of only {session.lease_time}s "
                f"— very short lease may cause repeated re-authentication"
            )

        # Slow DISCOVER -> ACK (over 3 seconds) means a sluggish DHCP path
        if session.discover_time and session.ack_time:
            elapsed = session.ack_time - session.discover_time
            if elapsed > 3.0:
                anomalies.append(
                    f"DHCP: {mac} took {elapsed:.1f}s to complete "
                    f"DISCOVER->ACK — slow DHCP server or network path issue"
                )

    return anomalies
