"""
generate_test_pcaps.py
Generates two realistic PCAP files for demonstration:
  - youtube_traffic.pcap  (YouTube TLS SNI + DNS + HTTP)
  - chatgpt_traffic.pcap  (ChatGPT/OpenAI TLS SNI + DNS)

Packet structure matches exactly what PacketParser.java / SniExtractor.java expects:
  Ethernet (14 B) + IPv4 (20 B) + TCP/UDP (20/8 B) + Payload
"""

import struct, time, random, os

OUT_DIR = r"C:\Users\rahul\Downloads\Packet_analyzer-main"

# ─── PCAP File Helpers ────────────────────────────────────────────────────────

def pcap_global_header():
    # magic, ver_maj, ver_min, tz, sigfigs, snaplen, link_type(1=Ethernet)
    return struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def pcap_pkt_header(data, ts_sec, ts_usec=0):
    caplen = len(data)
    return struct.pack('<IIII', ts_sec, ts_usec, caplen, caplen)

# ─── Layer Builders ───────────────────────────────────────────────────────────

SRC_MAC = b'\xaa\xbb\xcc\x00\x00\x01'
DST_MAC = b'\xaa\xbb\xcc\x00\x00\x02'

def eth_hdr(ethertype=0x0800):
    return DST_MAC + SRC_MAC + struct.pack('>H', ethertype)

def checksum(data):
    if len(data) % 2: data += b'\x00'
    s = sum(struct.unpack('>%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def ipv4_hdr(src_ip, dst_ip, proto, payload_len):
    ihl       = 5
    ver_ihl   = (4 << 4) | ihl
    total_len = 20 + payload_len
    ident     = random.randint(1, 65535)
    flags_off = 0x4000   # DF flag
    ttl       = 64
    src = bytes(int(x) for x in src_ip.split('.'))
    dst = bytes(int(x) for x in dst_ip.split('.'))
    # build header with checksum=0 first
    hdr = struct.pack('>BBHHHBBH4s4s',
        ver_ihl, 0, total_len, ident, flags_off, ttl, proto, 0, src, dst)
    csum = checksum(hdr)
    return struct.pack('>BBHHHBBH4s4s',
        ver_ihl, 0, total_len, ident, flags_off, ttl, proto, csum, src, dst)

def tcp_hdr(sport, dport, seq=1000, ack=0, flags=0x018):
    # data_offset=5 (20 bytes), flags in low byte
    data_off_flags = (5 << 12) | flags
    return struct.pack('>HHIIHHHH',
        sport, dport, seq, ack, data_off_flags, 65535, 0, 0)

def udp_hdr(sport, dport, payload_len):
    length = 8 + payload_len
    return struct.pack('>HHHH', sport, dport, length, 0)

# ─── TLS ClientHello with SNI ────────────────────────────────────────────────

def tls_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode()
    sni_len   = len(sni_bytes)

    # SNI extension payload:
    #   server_name_list_len (2) + type (1) + name_len (2) + name
    sni_entry = struct.pack('>BH', 0, sni_len) + sni_bytes          # type=host_name(0)
    sni_list  = struct.pack('>H', len(sni_entry)) + sni_entry        # list length + entry
    sni_ext   = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list # ext_type=0, ext_len, data

    # supported_groups extension (dummy)
    sg_data = struct.pack('>HHH', 2, 0x001d, 0x0017)                 # x25519, secp256r1
    sg_ext  = struct.pack('>HH', 0x000a, 4) + sg_data[:4]

    extensions = sni_ext + sg_ext
    ext_field  = struct.pack('>H', len(extensions)) + extensions

    client_random = bytes(range(32))                  # fixed 32-byte random
    session_id    = b'\x00'                           # empty session
    cipher_suites = struct.pack('>HHH', 4, 0xc02b, 0xc02c)  # ECDHE-ECDSA
    compression   = b'\x01\x00'                       # null compression

    hello_body = (b'\x03\x03' + client_random + session_id +
                  cipher_suites + compression + ext_field)

    # Handshake header: type=1(ClientHello), length (3 bytes)
    handshake = bytes([0x01]) + struct.pack('>I', len(hello_body))[1:] + hello_body

    # TLS record: content_type=0x16, version=TLS 1.0(0x0301), length
    record = struct.pack('>BHH', 0x16, 0x0301, len(handshake)) + handshake
    return record

# ─── DNS Query Packet ─────────────────────────────────────────────────────────

def dns_query(domain: str) -> bytes:
    txid  = random.randint(1, 65535)
    flags = 0x0100   # standard query, recursion desired
    hdr   = struct.pack('>HHHHHH', txid, flags, 1, 0, 0, 0)
    qname = b''
    for label in domain.split('.'):
        enc = label.encode()
        qname += bytes([len(enc)]) + enc
    qname += b'\x00'
    question = qname + struct.pack('>HH', 1, 1)  # QTYPE=A, QCLASS=IN
    return hdr + question

# ─── Full packet builders ─────────────────────────────────────────────────────

def make_tcp_tls(src_ip, dst_ip, sport, sni, seq=1000):
    payload = tls_client_hello(sni)
    t  = tcp_hdr(sport, 443, seq=seq, flags=0x018)   # PSH+ACK
    ip = ipv4_hdr(src_ip, dst_ip, 6, len(t) + len(payload))
    return eth_hdr() + ip + t + payload

def make_udp_dns(src_ip, dns_ip, domain):
    payload = dns_query(domain)
    sport   = random.randint(1024, 65535)
    u  = udp_hdr(sport, 53, len(payload))
    ip = ipv4_hdr(src_ip, dns_ip, 17, len(u) + len(payload))
    return eth_hdr() + ip + u + payload

def make_http_get(src_ip, dst_ip, sport, host, path='/'):
    """HTTP/1.1 GET — detected by SniExtractor.isHttpRequest()"""
    request = (f"GET {path} HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"User-Agent: Mozilla/5.0\r\n"
               f"Accept: */*\r\n\r\n").encode()
    t  = tcp_hdr(sport, 80, seq=random.randint(1000, 50000), flags=0x018)
    ip = ipv4_hdr(src_ip, dst_ip, 6, len(t) + len(request))
    return eth_hdr() + ip + t + request

# ─── Write PCAP ───────────────────────────────────────────────────────────────

def write_pcap(filename, packets):
    ts_base = int(time.time()) - len(packets)   # space them 1 sec apart
    with open(filename, 'wb') as f:
        f.write(pcap_global_header())
        for i, pkt in enumerate(packets):
            f.write(pcap_pkt_header(pkt, ts_base + i, i * 12000))
            f.write(pkt)
    print(f"[+] Written {len(packets)} packets → {filename}")

# ─── YouTube PCAP ────────────────────────────────────────────────────────────

def create_youtube_pcap(path):
    SRC  = '192.168.1.100'
    DNS  = '8.8.8.8'
    pkts = []

    # ── DNS queries ──
    for domain in ['youtube.com', 'www.youtube.com',
                   'googlevideo.com', 'yt3.ggpht.com',
                   'ytimg.com', 'youtube-nocookie.com']:
        pkts.append(make_udp_dns(SRC, DNS, domain))

    # ── TLS ClientHello (HTTPS port 443) ──
    yt_ips  = ['142.250.195.46', '216.58.200.78', '142.250.4.190', '172.217.14.110']
    yt_snis = [
        'youtube.com',
        'www.youtube.com',
        'googlevideo.com',
        'youtubei.googleapis.com',
        'yt3.ggpht.com',
        'accounts.google.com',
        'youtube.com',           # second connection (autoplay)
        'googlevideo.com',       # video stream
    ]
    for i, sni in enumerate(yt_snis):
        sport = 50000 + i
        dst   = random.choice(yt_ips)
        pkts.append(make_tcp_tls(SRC, dst, sport, sni, seq=1000 + i * 500))

    # ── HTTP (non-encrypted old YouTube redirect) ──
    pkts.append(make_http_get(SRC, '142.250.195.46', 55000, 'www.youtube.com'))

    write_pcap(path, pkts)

# ─── ChatGPT PCAP ────────────────────────────────────────────────────────────

def create_chatgpt_pcap(path):
    SRC  = '192.168.1.100'
    DNS  = '8.8.8.8'
    pkts = []

    # ── DNS queries ──
    for domain in ['chat.openai.com', 'openai.com',
                   'chatgpt.com', 'api.openai.com',
                   'cdn.oaistatic.com', 'auth.openai.com']:
        pkts.append(make_udp_dns(SRC, DNS, domain))

    # ── TLS ClientHello (HTTPS) ──
    gpt_ips  = ['104.18.32.7', '172.64.155.209', '104.18.33.7', '13.107.246.9']
    gpt_snis = [
        'chat.openai.com',
        'openai.com',
        'chatgpt.com',
        'api.openai.com',
        'cdn.oaistatic.com',
        'auth.openai.com',
        'chat.openai.com',      # second chat session
        'api.openai.com',       # API call (stream response)
    ]
    for i, sni in enumerate(gpt_snis):
        sport = 51000 + i
        dst   = random.choice(gpt_ips)
        pkts.append(make_tcp_tls(SRC, dst, sport, sni, seq=2000 + i * 500))

    # ── HTTP ──
    pkts.append(make_http_get(SRC, '104.18.32.7', 56000, 'openai.com'))

    write_pcap(path, pkts)

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    yt_file  = os.path.join(OUT_DIR, 'youtube_traffic.pcap')
    gpt_file = os.path.join(OUT_DIR, 'chatgpt_traffic.pcap')

    create_youtube_pcap(yt_file)
    create_chatgpt_pcap(gpt_file)

    print()
    print("=" * 55)
    print("  Test PCAP files created successfully!")
    print("=" * 55)
    print(f"  YouTube  → {yt_file}")
    print(f"  ChatGPT  → {gpt_file}")
    print()
    print("  Upload these to http://localhost:3000 to demo.")
    print("  To see BLOCKING in action, add these rules:")
    print()
    print("  [BLOCKED_APPS]")
    print("  YouTube")
    print()
    print("  [BLOCKED_DOMAINS]")
    print("  *.youtube.com")
    print("  *.openai.com")
    print("  chatgpt.com")
