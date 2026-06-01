# ================================================================
#  freq_utils.py
#  Wi-Fi channel and frequency utility functions
# ================================================================

def channel_to_frequency(channel):
    """
    Convert a Wi-Fi channel number to an approximate center frequency in MHz.
    Covers 2.4 GHz (ch 1-14), 5 GHz (ch 36-177), and 6 GHz (ch 1-233).
    Returns None if the channel cannot be mapped.
    """
    if channel is None:
        return None

    # 2.4 GHz band (channels 1-14)
    if 1 <= channel <= 14:
        return 2412 + 5 * (channel - 1)

    # 5 GHz band (common UNII channels)
    if 36 <= channel <= 177:
        return 5000 + 5 * channel

    # 6 GHz band (Wi-Fi 6E) - approximate
    if 1 <= channel <= 233:
        return 5955 + 5 * (channel - 1)

    return None


def frequency_to_band(freq):
    """
    Convert a frequency in MHz to a human-readable band string.
    Returns '2.4GHz', '5GHz', '6GHz', or 'Unknown'.
    """
    if freq is None:
        return "Unknown"
    if 2400 <= freq < 2500:
        return "2.4GHz"
    if 5000 <= freq < 5900:
        return "5GHz"
    if 5900 <= freq < 7125:
        return "6GHz"
    return "Unknown"
