# ================================================================
#  status_codes.py
#  IEEE 802.11 status and reason code lookup tables.
#  Source: IEEE 802.11-2020 Table 9-50 and Table 9-49
# ================================================================

# Status codes appear in Auth, Assoc, and Reassoc response frames.
# Code 0 = success. Everything else is a specific failure reason.
STATUS_CODES = {
    0:  ("SUCCESS",                          "Association or authentication successful"),
    1:  ("UNSPECIFIED_FAILURE",              "Unspecified failure — check controller logs"),
    10: ("CAPABILITIES_MISMATCH",            "AP cannot support all requested capabilities"),
    11: ("NO_REASSOC",                       "Reassociation denied — prior association not found"),
    12: ("OUT_OF_RANGE",                     "Association denied — client out of range"),
    13: ("AUTH_ALG_UNSUPPORTED",             "Authentication algorithm not supported by AP"),
    14: ("AUTH_SEQ_UNEXPECTED",              "Unexpected authentication sequence number"),
    15: ("AUTH_CHALLENGE_FAILURE",           "Challenge failure — likely a PSK mismatch"),
    16: ("AUTH_TIMEOUT",                     "Authentication rejected due to timeout"),
    17: ("AP_FULL",                          "AP unable to handle additional associated clients"),
    18: ("RATE_MISMATCH",                    "Client does not support AP's basic rate set"),
    19: ("SHORT_PREAMBLE_UNSUPPORTED",       "Short preamble not supported"),
    23: ("IEEE8021X_FAILED",                 "802.1X authentication failed — check RADIUS"),
    24: ("PMKID_INVALID",                    "PMKSA cache entry not valid — stale credentials"),
    28: ("INVALID_AKMP",                     "Invalid AKM — cipher suite negotiation failed"),
    30: ("RSN_IE_MISMATCH",                  "RSN information element contents are invalid"),
    31: ("CIPHER_SUITE_REJECTED",            "Cipher suite rejected per security policy"),
    33: ("INVALID_PMKID",                    "Invalid PMKID in RSN IE"),
    34: ("INVALID_MDE",                      "Invalid Mobility Domain Element (802.11r issue)"),
    35: ("INVALID_FTE",                      "Invalid Fast Transition Element"),
    37: ("TRANSMISSION_FAILURE",             "Request rejected — transmission failure"),
    38: ("TCLAS_NOT_SUPPORTED",              "Requested TCLAS not supported by AP"),
    41: ("INVALID_RSNE",                     "RSN IE mismatch between Beacon and Assoc frame"),
    45: ("ANTI_CLOGGING_TOKEN_REQUIRED",     "SAE anti-clogging token required"),
    46: ("FINITE_CYCLIC_GROUP_UNSUPPORTED",  "SAE finite cyclic group not supported"),
    47: ("TRANSITION_NOT_ALLOWED",           "Transition not allowed at this time"),
    72: ("MLD_LINK_KDE_MISSING",             "Wi-Fi 7 MLO: Required Link KDE is missing"),
    73: ("MLD_MAC_ADDR_MISMATCH",            "Wi-Fi 7 MLO: MLD MAC address mismatch"),
    74: ("MLD_LINK_UNACCEPTABLE",            "Wi-Fi 7 MLO: Requested link is not acceptable"),
}

# Reason codes appear in Deauth and Disassoc frames.
REASON_CODES = {
    0:  ("RESERVED",                         "Reserved — should not appear in practice"),
    1:  ("UNSPECIFIED",                       "Unspecified reason"),
    2:  ("PREV_AUTH_INVALID",                 "Previous authentication is no longer valid"),
    3:  ("DEAUTH_LEAVING",                    "Client is leaving the BSS (normal disconnect)"),
    4:  ("INACTIVITY",                        "Disassociated due to inactivity — check idle timeout tuning"),
    5:  ("AP_OVERLOAD",                       "AP unable to handle all associated clients"),
    6:  ("CLASS2_FROM_NONAUTH",               "Client sent frame before authentication — roaming failure"),
    7:  ("CLASS3_FROM_NONASSOC",              "Client sent frame before association — state machine error"),
    8:  ("DISASSOC_LEAVING",                  "Client leaving ESS (normal roam)"),
    9:  ("NOT_AUTHENTICATED",                 "Client not authenticated with AP"),
    14: ("MIC_FAILURE",                       "MIC failure — possible attack or PSK mismatch"),
    15: ("HANDSHAKE_TIMEOUT",                 "4-way handshake timeout — PSK mismatch or slow RADIUS"),
    16: ("GROUP_KEY_UPDATE_TIMEOUT",          "Group key handshake timeout"),
    17: ("HANDSHAKE_IE_MISMATCH",             "IE in 4-way handshake differs from Assoc/Probe frames"),
    18: ("INVALID_GROUP_CIPHER",              "Invalid group cipher selected"),
    19: ("INVALID_PAIRWISE_CIPHER",           "Invalid pairwise cipher selected"),
    20: ("INVALID_AKMP",                      "Invalid AKM suite"),
    23: ("IEEE8021X_FAILED",                  "802.1X authentication failed"),
    24: ("CIPHER_SUITE_REJECTED",             "Cipher suite rejected per security policy"),
    34: ("TDLS_TEARDOWN_UNREACHABLE",         "TDLS peer unreachable"),
    35: ("TDLS_TEARDOWN_REQUESTED",           "TDLS teardown requested by peer"),
    36: ("SSP_REQUESTED_DISASSOC",            "Disassociation requested by SSP"),
    45: ("PEER_KICKED",                       "Authorized access limit reached — client kicked by policy"),
    46: ("AUTHORIZED_ACCESS_LIMIT",           "AP reached authorized access limit"),
    47: ("EXTERNAL_SERVICE_REQUIREMENTS",     "External service requirements not met"),
}

# Codes that almost always indicate infrastructure-level problems.
INFRASTRUCTURE_FAULT_STATUS = {23, 24, 28, 30, 31, 34, 35, 41}
INFRASTRUCTURE_FAULT_REASON = {14, 15, 16, 17, 23}


def lookup_status(code):
    return STATUS_CODES.get(code, (f"UNKNOWN_{code}", f"Undocumented status code {code}"))


def lookup_reason(code):
    return REASON_CODES.get(code, (f"UNKNOWN_{code}", f"Undocumented reason code {code}"))


def is_failure_status(code):
    return code != 0


def is_infrastructure_fault_status(code):
    return code in INFRASTRUCTURE_FAULT_STATUS


def is_infrastructure_fault_reason(code):
    return code in INFRASTRUCTURE_FAULT_REASON
