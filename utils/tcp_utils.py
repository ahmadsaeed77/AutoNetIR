def has_tcp_flag(flags_value, flag_mask):
    """
    Check whether a specific TCP flag is set.

    flags_value usually comes from PyShark as a hex value like:
    0x0002, 0x0010, 0x0014
    """
    if flags_value is None:
        return False

    try:
        flags_int = int(str(flags_value), 16)
        return (flags_int & flag_mask) != 0
    except (ValueError, TypeError):
        return False