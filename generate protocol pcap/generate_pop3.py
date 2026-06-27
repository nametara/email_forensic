from scapy.all import *

# ============================================================
#  🛠️  EDIT THIS SECTION - ADD YOUR OWN POP3 SESSIONS HERE
# ============================================================

SRC_MAC = "00:11:22:33:44:55"
DST_MAC = "66:77:88:99:aa:bb"

# Define your POP3 sessions. Each session downloads one email.
pop3_sessions = [
    {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",          # POP3 Server
        "username": "alice",
        "password": "secret123",
        "email_subject": "Hello from POP3",
        "email_body": "This is the first email downloaded via POP3.\nRegards,\nAlice"
    },
    {
        "src_ip": "192.168.1.101",
        "dst_ip": "10.0.0.2",
        "username": "bob",
        "password": "bobspass",
        "email_subject": "Important Report",
        "email_body": "Please find the Q2 report attached (mock).\nThanks,\nBob"
    }
    # 👆 Add more sessions here!
]

# ============================================================
#  🚀  GENERATOR ENGINE - DON'T EDIT BELOW
# ============================================================

def build_pop3_session(entry, idx):
    src_ip = entry["src_ip"]
    dst_ip = entry["dst_ip"]
    user = entry["username"]
    pwd = entry["password"]
    subject = entry["email_subject"]
    body = entry["email_body"]

    # Unique TCP ports and sequence numbers per stream
    sport = 50000 + idx
    dport = 110
    iseq = 1000 + (idx * 200000)
    iack = 2000 + (idx * 200000)

    eth = Ether(src=SRC_MAC, dst=DST_MAC)
    packets = []

    # --- TCP Handshake ---
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S", seq=iseq)
    packets.append(p)
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=iack, ack=iseq+1)
    packets.append(p)
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A", seq=iseq+1, ack=iack+1)
    packets.append(p)

    s = iseq + 1
    a = iack + 1

    # --- POP3 Conversation ---

    # S: +OK banner
    load = b"+OK POP3 server ready\r\n"
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p)
    a += len(load)

    # C: USER
    load = f"USER {user}\r\n".encode()
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p)
    s += len(load)

    # S: +OK
    load = b"+OK\r\n"
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p)
    a += len(load)

    # C: PASS
    load = f"PASS {pwd}\r\n".encode()
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p)
    s += len(load)

    # S: +OK (login successful)
    load = b"+OK Logged in\r\n"
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p)
    a += len(load)

    # C: LIST
    load = b"LIST\r\n"
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p)
    s += len(load)

    # S: +OK listing (1 email)
    load = b"+OK 1 messages\r\n1 512\r\n.\r\n"
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p)
    a += len(load)

    # C: RETR 1
    load = b"RETR 1\r\n"
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p)
    s += len(load)

    # S: +OK followed by the raw email (headers + body) and ending with \r\n.\r\n
    email_content = (
        f"From: {user}@example.com\r\n"
        f"To: receiver@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"\r\n"
        f"{body}\r\n"
        f".\r\n"
    )
    load = f"+OK 512 octets\r\n{email_content}".encode()
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p)
    a += len(load)

    # C: DELE 1
    load = b"DELE 1\r\n"
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p)
    s += len(load)

    # S: +OK deleted
    load = b"+OK deleted\r\n"
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p)
    a += len(load)

    # C: QUIT
    load = b"QUIT\r\n"
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p)
    s += len(load)

    # S: +OK bye
    load = b"+OK Bye\r\n"
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p)
    a += len(load)

    # --- TCP Teardown ---
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="FA", seq=a, ack=s)
    packets.append(p)
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="FA", seq=s, ack=a+1)
    packets.append(p)

    return packets


# --- Generate ---
all_packets = []
for idx, session in enumerate(pop3_sessions):
    print(f"Generating POP3 session #{idx+1}: {session['username']} -> {session['dst_ip']}")
    all_packets.extend(build_pop3_session(session, idx))

wrpcap("pop3_traffic.pcap", all_packets)
print(f"\n✅ SUCCESS! Generated {len(pop3_sessions)} POP3 sessions in 'pop3_traffic.pcap'")
print("Filter in Wireshark: 'pop'")