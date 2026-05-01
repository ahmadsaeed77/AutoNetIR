import ipaddress


def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)

        return not any([
            ip_obj.is_private,
            ip_obj.is_loopback,
            ip_obj.is_multicast,
            ip_obj.is_reserved,
            ip_obj.is_link_local
        ])

    except ValueError:
        return False