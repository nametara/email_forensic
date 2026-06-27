#!/usr/bin/env python3
"""
generate_pcap.py
Generates a multi-protocol PCAP file simulating realistic Laurentian University email traffic.
Uses real‑sounding names, email addresses, and detailed message content.
"""

from scapy.all import *
import time

# ================================================================
# CONFIGURATION
# ================================================================

SRC_MAC = "00:15:17:12:34:56"   # Student's NIC (Intel OUI)
DST_MAC = "00:1a:a0:ab:cd:ef"   # Campus router (Cisco OUI)

# --- Realistic Email Content -------------------------------------------------
# Scenario:
#   - David Mike (dmike23@laurentian.ca) asks Professor Sarah Johnson (sjohnson@laurentian.ca)
#     about an assignment.
#   - Professor Johnson replies with clarification.
#   - A phishing email pretends to be from "Laurentian IT Security" but is actually
#     from an external attacker, warning about a compromised account.

emails = {
    "benign": {
        "from": "David Mike <dmike23@laurentian.ca>",
        "to": "Dr. Sarah Johnson <sjohnson@laurentian.ca>",
        "subject": "Question about COSC 3010 Assignment 2",
        "body": """Dear Professor Johnson,

I hope you are having a good semester. I am working on Assignment 2 for COSC 3010 and I have a question about the second part.

The assignment description says we need to implement a binary search tree, but I'm not sure if we are allowed to use external libraries like 'collections' in Python. Could you clarify if we should implement the tree completely from scratch?

Also, is there a specific format for the output we need to follow? I want to make sure I don't lose marks.

Thank you for your time.

Best regards,
David Mike
Student ID: 001234567
COSC 3010, Section A"""
    },
    "reply": {
        "from": "Dr. Sarah Johnson <sjohnson@laurentian.ca>",
        "to": "David Mike <dmike23@laurentian.ca>",
        "subject": "RE: Question about COSC 3010 Assignment 2",
        "body": """Hello David,

Thank you for your email. To clarify:

- You are NOT allowed to use any external libraries for the BST implementation. Everything must be written from scratch in Python (no imports except for testing).
- The output format is specified in the assignment PDF: each operation should print the resulting tree in level order.

I would recommend writing unit tests for each function to ensure correctness. Feel free to drop by my office hours (Wednesday 2-4 PM) if you need further help.

Good luck with the assignment!

Best,
Dr. Johnson
Professor, Computer Science
Laurentian University"""
    },
    "phishing": {
        "from": "IT Security <security@laurentian-secure.ca>",   # fake domain
        "to": "David Mike <dmike23@laurentian.ca>",
        "subject": "⚠️ URGENT: Your Laurentian Account Has Been Locked",
        "body": """Dear David Mike,

We have detected suspicious login attempts on your Laurentian University email account from an unknown IP address (192.168.1.45) outside of Canada.

To prevent your account from being permanently suspended, you must verify your identity within 24 hours.

Click the link below to verify:
http://laurentian-verify.com/secure?user=dmike23

Failure to verify will result in permanent suspension of your account and all associated data.

This is an automated security alert. Please do not reply to this email.

Thank you,
Laurentian IT Security Team
Laurentian University"""
    }
}

# ================================================================
# SMTP, IMAP, POP3 builder functions (identical to before, unchanged)
# ================================================================

def build_smtp_session(email, src_ip, dst_ip, sport_base, idx):
    sender = email["from"]
    recipient = email["to"]
    subject = email["subject"]
    body = email["body"]

    sport = sport_base + idx
    dport = 25
    iseq = 1000 + (idx * 100000)
    iack = 2000 + (idx * 100000)

    eth_client = Ether(src=SRC_MAC, dst=DST_MAC)
    eth_server = Ether(src=DST_MAC, dst=SRC_MAC)

    packets = []

    # TCP handshake
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="S", seq=iseq))
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="SA", seq=iack, ack=iseq+1))
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="A", seq=iseq+1, ack=iack+1))

    s = iseq + 1
    a = iack + 1

    # SMTP commands
    load = b"220 mail.laurentian.ca ESMTP Postfix\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    load = b"EHLO student.laurentian.ca\r\n"
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    load = b"250-mail.laurentian.ca\r\n250-SIZE 51200000\r\n250 OK\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    # Email data (RFC 822)
    mail_data = f"From: {sender}\r\nTo: {recipient}\r\nSubject: {subject}\r\nDate: {time.strftime('%a, %d %b %Y %H:%M:%S +0000')}\r\n\r\n{body}\r\n"
    load = f"MAIL FROM:<{sender.split('<')[1].rstrip('>')}>\r\n".encode()
    load += f"RCPT TO:<{recipient.split('<')[1].rstrip('>')}>\r\n".encode()
    load += b"DATA\r\n"
    load += mail_data.encode()
    load += b".\r\n"

    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    load = b"250 Queued mail for delivery\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    # Teardown
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="FA", seq=a, ack=s))
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="FA", seq=s, ack=a+1))

    return packets


def build_imap_session(src_ip, dst_ip, username, password, email_content, idx):
    sport = 50000 + idx
    dport = 143
    iseq = 3000 + (idx * 100000)
    iack = 4000 + (idx * 100000)

    eth_client = Ether(src=SRC_MAC, dst=DST_MAC)
    eth_server = Ether(src=DST_MAC, dst=SRC_MAC)

    packets = []

    # TCP handshake
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="S", seq=iseq))
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="SA", seq=iack, ack=iseq+1))
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="A", seq=iseq+1, ack=iack+1))

    s = iseq + 1
    a = iack + 1

    # IMAP commands
    load = b"* OK IMAP4 server ready\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    load = f"A001 LOGIN {username} {password}\r\n".encode()
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    load = b"A001 OK LOGIN completed\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    load = b"A002 SELECT INBOX\r\n"
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    load = b"* FLAGS (\\Seen \\Deleted)\r\n* OK [PERMANENTFLAGS ()] \r\nA002 OK [READ-WRITE] SELECT completed\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    load = b"A003 FETCH 1 BODY[]\r\n"
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    size = len(email_content)
    load = f"* 1 FETCH (BODY[] {{{size}}}\r\n".encode()
    load += email_content.encode()
    load += b"\r\n"
    load += b"A003 OK FETCH completed\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    load = b"A004 LOGOUT\r\n"
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    load = b"* BYE LOGOUT received\r\nA004 OK LOGOUT completed\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    # Teardown
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="FA", seq=a, ack=s))
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="FA", seq=s, ack=a+1))

    return packets


def build_pop3_session(src_ip, dst_ip, username, password, email_content, idx):
    sport = 60000 + idx
    dport = 110
    iseq = 5000 + (idx * 100000)
    iack = 6000 + (idx * 100000)

    eth_client = Ether(src=SRC_MAC, dst=DST_MAC)
    eth_server = Ether(src=DST_MAC, dst=SRC_MAC)

    packets = []

    # TCP handshake
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="S", seq=iseq))
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="SA", seq=iack, ack=iseq+1))
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="A", seq=iseq+1, ack=iack+1))

    s = iseq + 1
    a = iack + 1

    # POP3 commands
    load = b"+OK POP3 server ready\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    load = f"USER {username}\r\n".encode()
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    load = b"+OK\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    load = f"PASS {password}\r\n".encode()
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    load = b"+OK Logged in\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    load = b"LIST\r\n"
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    load = b"+OK 1 messages\r\n1 512\r\n.\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    load = b"RETR 1\r\n"
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    size = len(email_content)
    load = f"+OK {size} octets\r\n{email_content}\r\n.\r\n".encode()
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    load = b"DELE 1\r\n"
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    load = b"+OK deleted\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    load = b"QUIT\r\n"
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="PA", seq=s, ack=a) / Raw(load=load))
    s += len(load)

    load = b"+OK Bye\r\n"
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="PA", seq=a, ack=s) / Raw(load=load))
    a += len(load)

    # Teardown
    packets.append(eth_server / IP(src=dst_ip, dst=src_ip, ttl=58) / TCP(sport=dport, dport=sport, flags="FA", seq=a, ack=s))
    packets.append(eth_client / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=dport, flags="FA", seq=s, ack=a+1))

    return packets


# ================================================================
# MAIN GENERATION
# ================================================================

if __name__ == "__main__":
    all_packets = []

    # 1. SMTP: David Mike -> Professor Johnson (benign)
    print("📧 Generating SMTP: David Mike -> Dr. Johnson (benign)")
    all_packets.extend(build_smtp_session(
        emails["benign"],
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        sport_base=40000,
        idx=0
    ))

    # 2. SMTP: Professor Johnson -> David Mike (benign reply)
    print("📧 Generating SMTP: Dr. Johnson -> David Mike (benign reply)")
    all_packets.extend(build_smtp_session(
        emails["reply"],
        src_ip="10.0.0.1",
        dst_ip="192.168.1.100",
        sport_base=40010,
        idx=1
    ))

    # 3. SMTP: Attacker (spoofing IT Security) -> David Mike (phishing)
    print("📧 Generating SMTP: Attacker -> David Mike (phishing)")
    all_packets.extend(build_smtp_session(
        emails["phishing"],
        src_ip="203.0.113.50",   # External attacker IP
        dst_ip="192.168.1.100",
        sport_base=40020,
        idx=2
    ))

    # 4. IMAP: David Mike logs in and retrieves the benign reply from Professor Johnson
    print("📨 Generating IMAP: David Mike checks INBOX (retrieves reply)")
    imap_email_content = (
        f"From: Dr. Sarah Johnson <sjohnson@laurentian.ca>\r\n"
        f"To: David Mike <dmike23@laurentian.ca>\r\n"
        f"Subject: RE: Question about COSC 3010 Assignment 2\r\n"
        f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000')}\r\n"
        f"\r\n"
        f"{emails['reply']['body']}\r\n"
    )
    all_packets.extend(build_imap_session(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        username="dmike23",
        password="securepass",
        email_content=imap_email_content,
        idx=0
    ))

    # 5. POP3: David Mike retrieves and deletes the phishing email
    print("📥 Generating POP3: David Mike downloads phishing email")
    pop3_email_content = (
        f"From: IT Security <security@laurentian-secure.ca>\r\n"
        f"To: David Mike <dmike23@laurentian.ca>\r\n"
        f"Subject: ⚠️ URGENT: Your Laurentian Account Has Been Locked\r\n"
        f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000')}\r\n"
        f"\r\n"
        f"{emails['phishing']['body']}\r\n"
    )
    all_packets.extend(build_pop3_session(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        username="dmike23",
        password="securepass",
        email_content=pop3_email_content,
        idx=0
    ))

    # Write the PCAP file
    wrpcap("laurentian_traffic.pcap", all_packets)

    print("\n✅ Successfully generated laurentian_traffic.pcap")
    print("   Protocol Breakdown:")
    print("   - 3 SMTP sessions (2 benign, 1 phishing)")
    print("   - 1 IMAP session (retrieved benign reply)")
    print("   - 1 POP3 session (retrieved phishing email)")
    print("\n📂 File: laurentian_traffic.pcap")
    print("🔍 Upload this file to your Phishing Email Detector to see the results.")