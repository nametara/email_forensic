from scapy.all import *

# ============================================================
#  🛠️  EDIT THIS SECTION - ADD YOUR OWN IMAP SESSIONS HERE
# ============================================================

SRC_MAC = "00:11:22:33:44:55"
DST_MAC = "66:77:88:99:aa:bb"

# Define your IMAP sessions. Each session logs in and downloads one email.
imap_sessions = [
    {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",          # IMAP Server
        "username": "alice",
        "password": "secret123",
        "email_subject": "Welcome to IMAP",
        "email_body": "This email was downloaded via IMAP FETCH.\nCheers,\nAdmin"
    },
    {
        "src_ip": "192.168.1.102",
        "dst_ip": "10.0.0.3",
        "username": "charlie",
        "password": "charlie_pass",
        "email_subject": "System Update",
        "email_body": "The system will be updated at midnight.\n- IT"
    }
    # 👆 Add more sessions here!
]

# ============================================================
#  🚀  GENERATOR ENGINE - DON'T EDIT BELOW
# ============================================================

def build_imap_session(entry, idx):
    src_ip = entry["src_ip"]
    dst_ip = entry["dst_ip"]
    user = entry["username"]
    pwd = entry["password"]
    subject = entry["email_subject"]
    body = entry["email_body"]

    # Unique ports and seq numbers
    sport = 60000 + idx
    dport = 143
    iseq = 1000 + (idx * 300000)
    iack = 2000 + (idx * 300000)

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
    tag = 1

    # --- IMAP Conversation ---

    # S: * OK banner
    load = b"* OK IMAP4 server ready\r\n"
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p)
    a += len(load)

    # C: A001 LOGIN
    load = f"A{tag:03d} LOGIN {user} {pwd}\r\n".encode()
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p)
    s += len(load)
    tag += 1

    # S: A001 OK (login success)
    load = f"A{tag-1:03d} OK LOGIN completed\r\n".encode()
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p)
    a += len(load)

    # C: A002 SELECT INBOX
    load = f"A{tag:03d} SELECT INBOX\r\n".encode()
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p)
    s += len(load)
    tag += 1

    # S: * OK and A002 OK
    load = b"* FLAGS (\\Seen \\Deleted)\r\n* OK [PERMANENTFLAGS ()] \r\n"
    load += f"A{tag-1:03d} OK [READ-WRITE] SELECT completed\r\n".encode()
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p)
    a += len(load)

    # C: A003 FETCH 1 BODY[]
    load = f"A{tag:03d} FETCH 1 BODY[]\r\n".encode()
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p)
    s += len(load)
    tag += 1

    # S: * 1 FETCH (BODY[] {size}\r\n email \r\n) A003 OK
    email_content = (
        f"From: {user}@example.com\r\n"
        f"To: receiver@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"\r\n"
        f"{body}\r\n"
    )
    size = len(email_content)
    load = f"* 1 FETCH (BODY[] {{{size}}}\r\n".encode()
    load += email_content.encode()
    load += b"\r\n"
    load += f"A{tag-1:03d} OK FETCH completed\r\n".encode()
    
    p = eth / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p)
    a += len(load)

    # C: A004 LOGOUT
    load = f"A{tag:03d} LOGOUT\r\n".encode()
    p = eth / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p)
    s += len(load)
    tag += 1

    # S: * BYE and A004 OK
    load = b"* BYE LOGOUT received\r\n"
    load += f"A{tag-1:03d} OK LOGOUT completed\r\n".encode()
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
for idx, session in enumerate(imap_sessions):
    print(f"Generating IMAP session #{idx+1}: {session['username']} -> {session['dst_ip']}")
    all_packets.extend(build_imap_session(session, idx))

wrpcap("imap_traffic.pcap", all_packets)
print(f"\n✅ SUCCESS! Generated {len(imap_sessions)} IMAP sessions in 'imap_traffic.pcap'")
print("Filter in Wireshark: 'imap'")