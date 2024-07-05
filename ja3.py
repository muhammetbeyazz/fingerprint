#!/usr/bin/env python
"""Generate JA3 fingerprints from PCAPs using Python."""

import argparse
import dpkt
import json
import socket
import binascii
import struct
import os
from hashlib import md5

import sys


GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}
# GREASE_TABLE Ref: https://tools.ietf.org/html/draft-davidben-tls-grease-00
SSL_PORT = 443
TLS_HANDSHAKE = 22

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3"
}

def convert_ip(value):
    """Convert an IP address from binary to text.

    :param value: Raw binary data to convert
    :type value: str
    :returns: str
    """
    try:
        return socket.inet_ntop(socket.AF_INET, value)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, value)


def parse_variable_array(buf, byte_len):
    """Unpack data from buffer of specific length.

    :param buf: Buffer to operate on
    :type buf: bytes
    :param byte_len: Length to process
    :type byte_len: int
    :returns: bytes, int
    """
    _SIZE_FORMATS = ['!B', '!H', '!I', '!I']
    assert byte_len <= 4
    size_format = _SIZE_FORMATS[byte_len - 1]
    padding = b'\x00' if byte_len == 3 else b''
    size = struct.unpack(size_format, padding + buf[:byte_len])[0]
    data = buf[byte_len:byte_len + size]

    return data, size + byte_len


def ntoh(buf):
    """Convert to network order.

    :param buf: Bytes to convert
    :type buf: bytearray
    :returns: int
    """
    if len(buf) == 1:
        return buf[0]
    elif len(buf) == 2:
        return struct.unpack('!H', buf)[0]
    elif len(buf) == 4:
        return struct.unpack('!I', buf)[0]
    else:
        raise ValueError('Invalid input buffer size for NTOH')


def convert_to_ja3_segment(data, element_width):
    """Convert a packed array of elements to a JA3 segment.

    :param data: Current PCAP buffer item
    :type: str
    :param element_width: Byte count to process at a time
    :type element_width: int
    :returns: str
    """
    int_vals = list()
    data = bytearray(data)
    if len(data) % element_width:
        message = '{count} is not a multiple of {width}'
        message = message.format(count=len(data), width=element_width)
        raise ValueError(message)

    for i in range(0, len(data), element_width):
        element = ntoh(data[i: i + element_width])
        if element not in GREASE_TABLE:
            int_vals.append(element)

    return "-".join(str(x) for x in int_vals)


def process_extensions(client_handshake):
    """Process any extra extensions and convert to a JA3 segment.

    :param client_handshake: Handshake data from the packet
    :type client_handshake: dpkt.ssl.TLSClientHello
    :returns: list
    """
    if not hasattr(client_handshake, "extensions"):
        # Needed to preserve commas on the join
        return ["", "", ""], None  # Include SNI as None when not available

    exts = list()
    elliptic_curve = ""
    elliptic_curve_point_format = ""
    sni = None  # Initialize SNI

    for ext_val, ext_data in client_handshake.extensions:
        if not GREASE_TABLE.get(ext_val):
            exts.append(ext_val)
        if ext_val == 0x0a:
            a, b = parse_variable_array(ext_data, 2)
            # Elliptic curve points (16 bit values)
            elliptic_curve = convert_to_ja3_segment(a, 2)
        elif ext_val == 0x0b:
            a, b = parse_variable_array(ext_data, 1)
            # Elliptic curve point formats (8 bit values)
            elliptic_curve_point_format = convert_to_ja3_segment(a, 1)
        elif ext_val == 0x00:  # SNI Extension
            sni_name_length = struct.unpack('!H', ext_data[3:5])[0]
            sni = ext_data[5:5 + sni_name_length].decode('utf-8')
        else:
            continue

    results = list()
    results.append("-".join([str(x) for x in exts]))
    results.append(elliptic_curve)
    results.append(elliptic_curve_point_format)
    return results, sni


def process_pcap(pcap, any_port=False, ja3_data=None):
    """Process packets within the PCAP.

    :param pcap: Opened PCAP file to be processed
    :type pcap: dpkt.pcap.Reader
    :param any_port: Whether or not to search for non-SSL ports
    :type any_port: bool
    """
    decoder = dpkt.ethernet.Ethernet
    linktype = pcap.datalink()
    if linktype == dpkt.pcap.DLT_LINUX_SLL:
        decoder = dpkt.sll.SLL
    elif linktype == dpkt.pcap.DLT_NULL or linktype == dpkt.pcap.DLT_LOOP:
        decoder = dpkt.loopback.Loopback

    results = list()
    packet_counter = 0  # Initialize packet counter

    for timestamp, buf in pcap:
        packet_counter += 1  # Increment packet counter at the start of the loop
        try:
            eth = decoder(buf)
        except Exception:
            continue

        if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            # We want an IP packet
            continue
        if not isinstance(eth.data.data, dpkt.tcp.TCP):
            # TCP only
            continue

        ip = eth.data
        tcp = ip.data

        if not (tcp.dport == SSL_PORT or tcp.sport == SSL_PORT or any_port):
            # Doesn't match SSL port or we are picky
            continue
        if len(tcp.data) <= 0:
            continue

        tls_handshake = bytearray(tcp.data)
        if tls_handshake[0] != TLS_HANDSHAKE:
            continue

        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(tcp.data)
        except (dpkt.ssl.SSL3Exception, dpkt.dpkt.NeedData):
            continue

        for record in records:
            if record.type != TLS_HANDSHAKE:
                continue
            if len(record.data) == 0:
                continue
            client_hello = bytearray(record.data)
            if client_hello[0] != 1:
                # We only want client HELLO
                continue

            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.dpkt.NeedData:
                # Looking for a handshake here
                continue
            if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
                # Still not the HELLO
                continue

            client_handshake = handshake.data
            buf, ptr = parse_variable_array(client_handshake.data, 1)
            buf, ptr = parse_variable_array(client_handshake.data[ptr:], 2)
            ja3 = [str(client_handshake.version)]

            # Cipher Suites (16 bit values)
            ja3_exts, sni = process_extensions(client_handshake)  # Capture the SNI
            ja3.append(convert_to_ja3_segment(buf, 2))
            ja3.extend(ja3_exts)  # Use extend to add the elements of ja3_exts to ja3
            ja3_str = ",".join(ja3)  # Convert list to string

#EKLENDİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİ
          #  ja3_digest = md5(ja3_str.encode()).hexdigest()
           # user_agent = find_user_agent(ja3_digest, ja3_data) if ja3_data else None

            ja3_digest = md5(ja3_str.encode()).hexdigest()
            user_agent, match_found = find_user_agent(ja3_digest, ja3_data) if ja3_data else (None, False)

#EKLENDİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİ

            record = {"packet_number": packet_counter,  # Include packet number in the record
                      "source_ip": convert_ip(ip.src),
                      "destination_ip": convert_ip(ip.dst),
                      "source_port": tcp.sport,
                      "destination_port": tcp.dport,
                      "tls_version": "{} (0x{:04x})".format(TLS_VERSIONS.get(client_handshake.version, "Unknown"), client_handshake.version),
                      "ja3": ja3_str,
                      "ja3_digest": md5(ja3_str.encode()).hexdigest(),
                      "user_agent": user_agent,  #EKLENDİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİ
                      "timestamp": timestamp,
                      "sni": sni,
                        "match_found": match_found,
                      "client_hello_pkt": binascii.hexlify(tcp.data).decode('utf-8')}
            results.append(record)

    return results  # Return the results after processing all packets


#EKELENDİİİİİİİİİİİİİİİİİİİİİ
def load_ja3_hashes(json_path):
    """Load JA3 hashes from a JSON file."""
    try:
        with open(json_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print("The specified JSON file was not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        return None

def find_user_agent(ja3_digest, ja3_data):
    """Find the user agent corresponding to a JA3 digest."""
    for entry in ja3_data:
        if entry['ja3_hash'] == ja3_digest:
            return entry['desc'], True  # 'desc' key contains the user agent
    return None, False

#EKELENDİİİİİİİİİİİİİİİİİİİİİ



def main():
    """Intake arguments from the user and print out JA3 output."""
    desc = "A python script for extracting JA3 fingerprints from PCAP files"
    usage_text = (
        f"\nja3 [-h] [-a] [-j] [-r] [-cf] [-o OUTPUT] pcap\n\n"
        f"Example: ja3 -cf /path/your/example.pcap\n"    
        f"Example: ja3 -j /path/your/example.pcap\n"
        f"Example: ja3 -cf -o /path/your/example.txt /path/your/example.pcap\n"
        f"Example: ja3 -j -o /path/your/example.json /path/your/example.pcap\n\n"
        f"Extract JA3 fingerprints with various options."      
        )
    parser = argparse.ArgumentParser(description=desc, usage=usage_text)
# Defining multiple arguments individually with help texts
    parser.add_argument("pcap", help="The PCAP file to process for extracting JA3 fingerprints")
    help_text = "Look for client hellos on any port instead of just 443"
    parser.add_argument("-a", "--any_port", required=False,
                        action="store_true", default=False,
                        help=help_text)
    help_text = "Print out as JSON records for downstream parsing"
    parser.add_argument("-j", "--json", required=False, action="store_true",
                        default=False, help=help_text)
    help_text = "Print packet related data for research (json only)"
    parser.add_argument("-r", "--research", required=False, action="store_true",
                        default=False, help=help_text)
    help_text = "Print output in custom format"
    parser.add_argument("-cf", "--customFormat", required=False, action="store_true", default=False, help=help_text)
    parser.add_argument("-o", "--output", required=False, type=str, metavar='OUTPUT_PATH',
                        help="(optional) Enable JSON or TXT formatted output. Must be used for output to be printed or saved.")
#EKLENDİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİ
    parser.add_argument("-k", "--compare", type=str, help="Compare JA3 hashes against a known list from a specified JSON file path")
#EKLENDİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİ
    args = parser.parse_args()


#EKLENDİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİ
    ja3_data = None
    if args.compare:
        ja3_data = load_ja3_hashes(args.compare)
#EKLENDİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİİ


    # Use an iterator to process each line of the file
    output = None
    with open(args.pcap, 'rb') as fp:
        try:
            capture = dpkt.pcap.Reader(fp)
        except ValueError as e_pcap:
            try:
                fp.seek(0, os.SEEK_SET)
                capture = dpkt.pcapng.Reader(fp)
            except ValueError as e_pcapng:
                raise Exception(
                        "File doesn't appear to be a PCAP or PCAPng: %s, %s" %
                        (e_pcap, e_pcapng))
        output = process_pcap(capture, any_port=args.any_port, ja3_data=ja3_data)


        # ANSI escape code for green color
        RED = '\033[91m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        CYAN = '\033[36m'
        MAGENTA = '\033[95m'
        GREEN = '\033[92m'
        RESET = '\033[0m'


    if args.customFormat:
        print()
        header = (
            f"{RED}Fingerprint Matched !!{RESET}\n\n"
            f"{CYAN}No\t\tUserAgent:Md5Hash\t\t  ProtcolVersion\t\t     SrcIP;SrcPort\t  DestIP:DestPort\t\t    ServerName{RESET}"
        )
    
        print(header)

        # Prepare the text output without ANSI color codes
        txt_output = "Fingerprint Matched !!\n\n"
        txt_output += "No\t\t UserAgent:Md5Hash\t\t   ProtcolVersion\t\t      SrcIP;SrcPort\t   DestIP:DestPort\t\t     ServerName\n\n"

        for record in output:
            print()
            line = (f"{YELLOW}{record['packet_number']}:{RESET} {BLUE}'{record['user_agent']}:{RESET}{GREEN}{record['ja3_digest']}'{RESET} {YELLOW}'{record['tls_version']}'{RESET} Connection From {YELLOW}'{record['source_ip']}:{record['source_port']}'{RESET} to {YELLOW}'{record['destination_ip']}:{record['destination_port']}'{RESET} ServerName: {BLUE}'{record['sni']}'{RESET}") 
            file_line = (f"{record['packet_number']}: '{record['user_agent']}:{record['ja3_digest']}' '{record['tls_version']}' Connection From '{record['source_ip']}:{record['source_port']}' to '{record['destination_ip']}:{record['destination_port']}' ServerName: '{record['sni']}'") 
            txt_output += file_line + "\n\n"
            print(line)
            
        if args.output:
            pcap_path = os.path.abspath(args.pcap) if args.pcap else "Belirtilmemiş"
            file_path = os.path.abspath(args.output)
            file_name = os.path.basename(args.output) 
            # .txt uzantısı kontrolü eklendi
            if not args.output.endswith(".txt"):
                print(f"\n\n{RED}Hata: Dosya kayıt edilmedi. Çıktı dosyası .txt uzantılı olmalıdır!{RESET}")
                print(f"{RED}Örnek Kullanım:{RESET} {CYAN}'ja3 -cf -o{RESET} {GREEN}/path/your/example.txt{RESET} {CYAN}{pcap_path}'{RESET}")
            else:
                with open(args.output, "w") as f:
                    f.write(txt_output)

                # Print the success message to the console
                print(f"\n{GREEN}Dosya başarıyla kaydedildi!{RESET}")
                print(f"{GREEN}Dosya Adı:{RESET} {file_name}")
                print(f"{GREEN}Dosya Yolu:{RESET} {file_path}")

    elif args.json:
        if not args.research:
            for record in output:
                if 'packet_number' in record:
                    del record['packet_number']
                if 'client_hello_pkt' in record:
                    del record['client_hello_pkt']
        json_output = json.dumps(output, indent=4, sort_keys=True)
        print(json_output)
        if args.output:
            pcap_path = os.path.abspath(args.pcap) if args.pcap else "Belirtilmemiş"
            file_path = os.path.abspath(args.output)
            file_name = os.path.basename(args.output)
            # .txt uzantısı kontrolü eklendi
            if not args.output.endswith(".json"):
                print(f"\n\n{RED}Hata: Dosya kayıt edilmedi. Çıktı dosyası .json uzantılı olmalıdır!{RESET}")
                print(f"{RED}Örnek Kullanım:{RESET} {CYAN}'ja3 -j -o{RESET} {GREEN}/path/your/example.json{RESET} {CYAN}{pcap_path}'{RESET}")
            else:
                with open(args.output, "w") as f:
                    f.write(json_output)


                    match_status = "Matched" if record['match_found'] else "Not Matched"
                    print(f"JA3 Digest {record['ja3_digest']} -> {match_status}")

                    # Print the success message to the console
                    print(f"\n{GREEN}Dosya başarıyla kaydedildi!{RESET}")
                    print(f"{GREEN}Dosya Adı:{RESET} {file_name}")
                    print(f"{GREEN}Dosya Yolu:{RESET} {file_path}")
                
    else:
        for record in output:
            tmp = '[{dest}:{port}] JA3: {segment} --> {digest}'
            tmp = tmp.format(dest=record['destination_ip'],
                             port=record['destination_port'],
			     version=record['tls_version'],
                             segment=record['ja3'],
                             digest=record['ja3_digest'])
            print(tmp)


if __name__ == "__main__":
        main()
