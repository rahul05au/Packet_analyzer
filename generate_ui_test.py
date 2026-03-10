import struct
import time

def generate_test_pcap(filename):
    with open(filename, 'wb') as f:
        # PCAP Global Header
        f.write(struct.pack('<I', 0xa1b2c3d4)) # Magic
        f.write(struct.pack('<H', 2))          # Major
        f.write(struct.pack('<H', 4))          # Minor
        f.write(struct.pack('<I', 0))          # thiszone
        f.write(struct.pack('<I', 0))          # sigfigs
        f.write(struct.pack('<I', 65535))      # snaplen
        f.write(struct.pack('<I', 1))          # network (Ethernet)

        print(f"Created {filename} with a test packet.")

        # Let's add one dummy TCP packet to avoid empty file logic
        # 16-byte Packet header
        ts = int(time.time())
        length = 54 # Eth(14) + IP(20) + TCP(20)
        f.write(struct.pack('<I', ts))
        f.write(struct.pack('<I', 0))
        f.write(struct.pack('<I', length))
        f.write(struct.pack('<I', length))

        # Ethernet
        f.write(b'\xaa\xbb\xcc\xdd\xee\xff')
        f.write(b'\x11\x22\x33\x44\x55\x66')
        f.write(b'\x08\x00') # IPv4

        # IP
        f.write(b'\x45\x00\x00\x28') # len 40
        f.write(b'\x00\x01\x00\x00\x40\x06')
        f.write(b'\x00\x00') # checksum
        f.write(b'\xc0\xa8\x01\x0a') # 192.168.1.10
        f.write(b'\xc0\xa8\x01\x32') # 192.168.1.50

        # TCP
        f.write(b'\x04\x00\x00\x50') # src 1024, dst 80
        f.write(b'\x00\x00\x00\x01\x00\x00\x00\x00')
        f.write(b'\x50\x02\x20\x00\x00\x00\x00\x00')

if __name__ == '__main__':
    generate_test_pcap("test_upload.pcap")
