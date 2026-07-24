from collections import defaultdict  # to store packets by flow
import shutil  # to remove and create directories
from pathlib import Path  # to find the parent directory

from scapy.all import IP, TCP, UDP, rdpcap, wrpcap  # to read and write pcap files

# Find the parent directory of the current file
base_dir = Path(__file__).resolve().parent
OUTPUT_DIR = base_dir / "flows"


def recog_flow(pkt):
    """pick up flow information from packet"""
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]

    if pkt.haslayer(TCP):
        t = pkt[TCP]
        return ("TCP", ip.src, t.sport, ip.dst, t.dport)

    if pkt.haslayer(UDP):
        u = pkt[UDP]
        return ("UDP", ip.src, u.sport, ip.dst, u.dport)

    return None


def session_key(flow):
    """merge bidirectional flow into a single session: sort endpoints, ignore direction"""
    proto, src, sport, dst, dport = flow
    endpoints = tuple(sorted([(src, sport), (dst, dport)]))
    return (proto, endpoints)


def session_label(session):
    proto, endpoints = session
    (a_ip, a_port), (b_ip, b_port) = endpoints
    return f"{proto} {a_ip}:{a_port} <-> {b_ip}:{b_port}"


def session_filename(session):
    proto, endpoints = session
    (a_ip, a_port), (b_ip, b_port) = endpoints
    return f"{proto}_{a_ip}_{a_port}_{b_ip}_{b_port}.pcap"


def session_bytes(pkts):
    return sum(len(pkt) for pkt in pkts)


def main():
    packets = rdpcap(str(base_dir / "test.pcap"))  # read pcap file
    sessions = defaultdict(list)  # dictionary to store packets by flow

    for pkt in packets:
        flow = recog_flow(pkt)  # recognize flow from packet
        if flow:
            sessions[session_key(flow)].append(
                pkt
            )  # dictionary to store packets by flow

    # based on time order, export pcap files in correct order
    for pkts in sessions.values():
        pkts.sort(key=lambda p: p.time)  # sort packets by time

    ranked_by_pkts = sorted(
        sessions.items(), key=lambda item: len(item[1]), reverse=True
    )
    ranked_by_bytes = sorted(
        sessions.items(), key=lambda item: session_bytes(item[1]), reverse=True
    )

    print(f"Total: {len(packets)}")  # total number of packets
    print(f"Sessions: {len(sessions)}\n")  # total number of sessions
    print("=== Top 10 sessions (by packets) ===")
    for session, pkts in ranked_by_pkts[:10]:  # print top 10 sessions by packets
        print(f"  {len(pkts):>6} pkts  {session_label(session)}")

    print("\n=== Top 10 sessions (by bytes) ===")
    for session, pkts in ranked_by_bytes[:10]:  # print top 10 sessions by bytes
        print(f"  {session_bytes(pkts):>10} bytes  {session_label(session)}")

    if OUTPUT_DIR.exists():  # check if old_directory exists
        shutil.rmtree(OUTPUT_DIR)  # remove old_directory if it exists
    OUTPUT_DIR.mkdir()  # create new_directory
    for session, pkts in ranked_by_pkts:  # export sessions by packets
        out_path = OUTPUT_DIR / session_filename(session)  # create new_directory path
        wrpcap(str(out_path), pkts)  # write packets to new_directory path

    print(
        f"\n{len(sessions)} sessions exported to {OUTPUT_DIR}/"
    )  # print number of sessions exported


if __name__ == "__main__":
    main()
