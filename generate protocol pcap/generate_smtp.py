from scapy.all import *

# ============================================================
#  CONFIGURATION - Add your own emails here
# ============================================================

# MAC addresses (using real vendor OUIs)
SRC_MAC = "00:15:17:12:34:56"  # Intel NIC
DST_MAC = "00:1a:a0:ab:cd:ef"  # Cisco Router

# Define the list of emails to generate
emails_to_generate = [
    {
        "src_ip": "203.0.113.10",      # Public client IP
        "dst_ip": "198.51.100.25",     # Public mail server IP
        "sender": "alice@real-company.com",
        "recipient": "bob@example.com",
        "subject": "Meeting Tomorrow",
        "body": "Hi Bob,\nLet's meet at 10 AM in Room 4.\nCheers,\nAlice"
    },
    {
        "src_ip": "203.0.113.10",
        "dst_ip": "198.51.100.25",
        "sender": "spam@spammer.com",
        "recipient": "victim@domain.com",
        "subject": "YOU WON A PRIZE!!!",
        # This is the classic phishing content you want to detect
        "body": "Click this link to claim your million dollars!\nhttp://fake-link.com"
    },
    {
        "src_ip": "203.0.113.11",
        "dst_ip": "198.51.100.26",
        "sender": "hr@bigcorp.com",
        "recipient": "employee@bigcorp.com",
        "subject": "Your Payroll Update",
        "body": "Dear Employee,\nYour salary has been updated in the system.\nRegards,\nHR"
    }
]

# ============================================================
#  GENERATION ENGINE (Do not modify below this line)
# ============================================================

def build_smtp_stream(entry, idx):
    src_ip = entry["src_ip"]
    dst_ip = entry["dst_ip"]
    sender = entry["sender"]
    recipient = entry["recipient"]
    subject = entry["subject"]
    body = entry["body"]

    sport = 40000 + idx
    dport = 25
    iseq = 1000 + (idx * 100000)
    iack = 2000 + (idx * 100000)

    # Realistic TTL values (simulating multiple router hops)
    CLIENT_TTL = 64
    SERVER_TTL = 58

    eth_client = Ether(src=SRC_MAC, dst=DST_MAC)
    eth_server = Ether(src=DST_MAC, dst=SRC_MAC)

    packets = []

    # 1. TCP 3-Way Handshake
    p = eth_client / IP(src=src_ip, dst=dst_ip, ttl=CLIENT_TTL) / TCP(sport=sport, dport=dport, flags="S", seq=iseq)
    packets.append(p)
    p = eth_server / IP(src=dst_ip, dst=src_ip, ttl=SERVER_TTL) / TCP(sport=dport, dport=sport, flags="SA", seq=iack, ack=iseq+1)
    packets.append(p)
    p = eth_client / IP(src=src_ip, dst=dst_ip, ttl=CLIENT_TTL) / TCP(sport=sport, dport=dport, flags="A", seq=iseq+1, ack=iack+1)
    packets.append(p)

    s = iseq + 1
    a = iack + 1

    # 2. SMTP Command Exchange
    # S: 220 Banner
    load = b"220 mail.real-server.com ESMTP Postfix\r\n"
    p = eth_server / IP(src=dst_ip, dst=src_ip, ttl=SERVER_TTL) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p); a += len(load)

    # C: EHLO
    load = b"EHLO client.real-isp.com\r\n"
    p = eth_client / IP(src=src_ip, dst=dst_ip, ttl=CLIENT_TTL) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p); s += len(load)

    # S: 250 Response
    load = b"250-mail.real-server.com\r\n250-SIZE 51200000\r\n250 OK\r\n"
    p = eth_server / IP(src=dst_ip, dst=src_ip, ttl=SERVER_TTL) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p); a += len(load)

    # C: MAIL FROM, RCPT TO, DATA + Complete mail headers (Critical Fix)
    load = f"MAIL FROM:<{sender}>\r\n".encode()
    load += f"RCPT TO:<{recipient}>\r\n".encode()
    load += b"DATA\r\n"
    # The following 3 lines add standard mail headers to fix "Unknown" From/To fields
    load += f"From: {sender}\r\n".encode()
    load += f"To: {recipient}\r\n".encode()
    load += f"Subject: {subject}\r\n".encode()
    load += b"\r\n"  # End of headers, start of body
    load += f"{body}\r\n".encode()
    load += b".\r\n"

    p = eth_client / IP(src=src_ip, dst=dst_ip, ttl=CLIENT_TTL) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load)
    packets.append(p); s += len(load)

    # S: 250 OK
    load = b"250 Queued mail for delivery\r\n"
    p = eth_server / IP(src=dst_ip, dst=src_ip, ttl=SERVER_TTL) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load)
    packets.append(p); a += len(load)

    # 3. TCP Connection Teardown
    p = eth_server / IP(src=dst_ip, dst=src_ip, ttl=SERVER_TTL) / TCP(sport=dport, dport=sport, flags="FA", seq=a, ack=s)
    packets.append(p)
    p = eth_client / IP(src=src_ip, dst=dst_ip, ttl=CLIENT_TTL) / TCP(sport=sport, dport=dport, flags="FA", seq=s, ack=a+1)
    packets.append(p)

    return packets


# Generate and save
print("🌐 Generating SMTP PCAP with complete mail headers...")
all_packets = []
for idx, email in enumerate(emails_to_generate):
    print(f"  Email #{idx+1}: {email['sender']} -> {email['recipient']}")
    all_packets.extend(build_smtp_stream(email, idx))

wrpcap("smtp_traffic.pcap", all_packets)
print(f"\n✅ Successfully generated {len(emails_to_generate)} emails in 'smtp_traffic.pcap'")
print("🔍 Now open phishing_detector.html and upload this file for analysis")