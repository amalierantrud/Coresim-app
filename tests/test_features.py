from otdiag import aggregate_minutes, parse_tcpdump_line, minute_stats_from_row


def test_parse_udp_line_from_coresim():
    p = parse_tcpdump_line("2025-11-27 10:25:13.546932 IP 192.168.10.116.11621 > 224.10.10.116.21621: UDP, length 996")
    assert p.src_ip == "192.168.10.116" and p.src_port == 11621
    assert p.dst_ip == "224.10.10.116" and p.dst_port == 21621
    assert p.proto == "UDP" and p.length == 996


def test_parse_tcp_syn_and_hsrp():
    syn = parse_tcpdump_line("2026-01-01 12:00:00.000001 IP 10.0.0.66.40000 > 192.168.10.101.502: Flags [S], seq 1, win 1024, length 0")
    assert syn.proto == "TCP" and syn.tcp_flags == "S" and syn.dst_port == 502
    hsrp = parse_tcpdump_line("2025-11-27 10:25:12.806562 IP 192.168.10.1 > 224.0.0.2: HSRPv1-hello 20: state=active")
    assert hsrp.proto == "HSRP" and hsrp.src_port is None


def test_garbage_is_ignored():
    assert parse_tcpdump_line("\\x00\\x00 h2http/1.1") is None
    assert parse_tcpdump_line("") is None


def test_aggregate_counts_packets_bytes_and_ports():
    lines = [
        "2026-01-01 12:00:01.0 IP 1.1.1.1.5 > 2.2.2.2.80: UDP, length 100",
        "2026-01-01 12:00:30.0 IP 1.1.1.1.5 > 2.2.2.2.81: UDP, length 300",
        "2026-01-01 12:01:00.0 IP 1.1.1.1.5 > 2.2.2.2.80: UDP, length 100",
    ]
    stats = list(aggregate_minutes(map(parse_tcpdump_line, lines)))
    assert len(stats) == 2
    first = stats[0]
    assert (first.packets, first.bytes, first.dest_ports, first.avg_len) == (2, 400, 2, 200.0)


def test_row_from_splunk_summary():
    s = minute_stats_from_row({"_time": "1792998000", "src_ip": "a", "dest_ip": "b", "proto": "UDP",
                               "packets": "10", "bytes": "1000", "dest_ports": "1"})
    assert s.packets == 10 and s.avg_len == 100
