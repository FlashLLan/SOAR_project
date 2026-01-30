def parse_alert(record):
    """
    record = dict loaded from JSON per EVE line
    """
    alert = record.get("alert", {})

    return {
        "timestamp": record.get("timestamp"),
        "src_ip": record.get("src_ip"),
        "src_port": record.get("src_port"),
        "dest_ip": record.get("dest_ip"),
        "dest_port": record.get("dest_port"),
        "proto": record.get("proto"),
        "signature": alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "category": alert.get("category"),
        "severity": alert.get("severity")
    }
