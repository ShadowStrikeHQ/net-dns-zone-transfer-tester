#!/usr/bin/env python3

import argparse
import socket
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Attempts to perform a DNS zone transfer from a specified nameserver to identify potential misconfigurations."
    )
    parser.add_argument("domain", help="The domain to attempt a zone transfer on.")
    parser.add_argument("nameserver", help="The nameserver to target for the zone transfer.")
    parser.add_argument(
        "-t",
        "--tcp",
        action="store_true",
        help="Use TCP for the zone transfer (default is UDP).",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=53,
        help="The port to connect to on the nameserver (default is 53).",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output."
    )
    return parser.parse_args()


def perform_zone_transfer(domain, nameserver, port=53, use_tcp=False):
    """
    Attempts to perform a DNS zone transfer using AXFR.

    Args:
        domain (str): The domain to attempt the zone transfer on.
        nameserver (str): The nameserver to target.
        port (int): The port to connect to.
        use_tcp (bool): Whether to use TCP instead of UDP.

    Returns:
        list: A list of DNS records if the zone transfer is successful, None otherwise.
    """

    try:
        if use_tcp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # Set a timeout to prevent indefinite hanging
            sock.connect((nameserver, port))

            # Construct AXFR query message
            query = bytearray()
            query.extend(b'\x00\x01')  # Transaction ID (arbitrary)
            query.extend(b'\x01\x00')  # Flags: Standard query, recursion desired
            query.extend(b'\x00\x01')  # Questions: 1
            query.extend(b'\x00\x00')  # Answer RRs: 0
            query.extend(b'\x00\x00')  # Authority RRs: 0
            query.extend(b'\x00\x00')  # Additional RRs: 0

            # Question section
            labels = domain.split('.')
            for label in labels:
                query.extend(bytes([len(label)]))
                query.extend(label.encode())
            query.extend(b'\x00') # Null terminator for the domain name
            query.extend(b'\x00\xfc') # QTYPE = AXFR
            query.extend(b'\x00\x01') # QCLASS = IN

            # Prepend the length of the message (2 bytes)
            length = len(query).to_bytes(2, 'big')
            message = length + query

            sock.sendall(message)

            # Receive data
            data = b''
            while True:
                chunk = sock.recv(4096) # Increased buffer size
                if not chunk:
                    break
                data += chunk

            sock.close()

            if not data:
                logging.warning("No data received from nameserver.")
                return None

            # Parse the response (very basic parsing, adjust for real use)
            records = []
            # Remove the 2 byte length field
            data = data[2:]
            # Simple extraction of potential records from the received data - requires a full DNS parser for complete parsing
            records_raw = data.split(b'\xc0\x0c') # Basic split based on common DNS pointer

            # Basic parsing of the returned records.
            for record in records_raw:
                record_str = record.decode('latin-1', errors='ignore') # decode the bytes.

                if len(record_str) > 10:
                    records.append(record_str)


            return records



        else:
            # UDP is generally not suitable for AXFR because of size limits.  However,
            # a TCP connection is required for AXFR zone transfer.  This UDP path is included for academic purposes and testing failure conditions.
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            query = bytearray()
            query.extend(b'\x00\x01')  # Transaction ID (arbitrary)
            query.extend(b'\x01\x00')  # Flags: Standard query, recursion desired
            query.extend(b'\x00\x01')  # Questions: 1
            query.extend(b'\x00\x00')  # Answer RRs: 0
            query.extend(b'\x00\x00')  # Authority RRs: 0
            query.extend(b'\x00\x00')  # Additional RRs: 0

            # Question section
            labels = domain.split('.')
            for label in labels:
                query.extend(bytes([len(label)]))
                query.extend(label.encode())
            query.extend(b'\x00')  # Null terminator for the domain name
            query.extend(b'\x00\xfc')  # QTYPE = AXFR
            query.extend(b'\x00\x01')  # QCLASS = IN

            sock.sendto(bytes(query), (nameserver, port))
            data, _ = sock.recvfrom(4096)  # UDP limit

            # In a real-world scenario, AXFR over UDP will likely be truncated.
            if len(data) > 512:
                logging.warning("Response truncated (likely due to UDP).  AXFR typically requires TCP.")
            sock.close()

            records = [data.decode('latin-1', errors='ignore')] # Basic extraction of returned records

            return records


    except socket.timeout:
        logging.error(f"Timeout connecting to {nameserver}:{port}")
        return None
    except socket.gaierror:
        logging.error(f"Could not resolve hostname: {nameserver}")
        return None
    except ConnectionRefusedError:
        logging.error(f"Connection refused by {nameserver}:{port}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def validate_domain(domain):
    """
    Validates that the input is a properly formatted domain name.
    Uses a basic check for valid characters and structure, not full RFC compliance.

    Args:
        domain (str): The domain name to validate.

    Returns:
        bool: True if the domain is valid, False otherwise.
    """
    if not isinstance(domain, str):
        return False

    if not all(c.isalnum() or c in ".-" for c in domain):
        return False

    if domain.startswith("-") or domain.endswith("-"):
        return False

    if ".." in domain:  # No consecutive dots
        return False

    labels = domain.split(".")
    if not all(len(label) > 0 and len(label) <= 63 for label in labels):
        return False

    if not all(label.isalnum() or (label.startswith(('xn--')) or (all(c.isalnum() or c == '-' for c in label))) for label in labels): # allow for IDNA domains.

        return False


    return True

def validate_nameserver(nameserver):
    """
    Validates that the input is a properly formatted hostname or IP address.

    Args:
        nameserver (str): The nameserver to validate.

    Returns:
        bool: True if the nameserver is valid, False otherwise.
    """
    try:
        socket.inet_aton(nameserver)  # Check if it's a valid IP address
        return True
    except socket.error:
        # Not a valid IP, try to resolve as a hostname
        try:
            socket.gethostbyname(nameserver) # Attempt to resolve hostname
            return True
        except socket.gaierror:
            return False
    except Exception:
        return False



def main():
    """
    Main function to parse arguments, validate inputs, and perform the zone transfer.
    """
    args = setup_argparse()

    domain = args.domain
    nameserver = args.nameserver
    port = args.port
    use_tcp = args.tcp
    verbose = args.verbose

    # Input validation
    if not validate_domain(domain):
        logging.error(f"Invalid domain name: {domain}")
        sys.exit(1)

    if not validate_nameserver(nameserver):
        logging.error(f"Invalid nameserver: {nameserver}")
        sys.exit(1)

    if not isinstance(port, int) or not (1 <= port <= 65535):
        logging.error(f"Invalid port number: {port}")
        sys.exit(1)

    logging.info(f"Attempting zone transfer for {domain} from {nameserver}:{port} (TCP: {use_tcp})")

    # Perform zone transfer
    records = perform_zone_transfer(domain, nameserver, port, use_tcp)

    if records:
        print("Zone transfer successful:")
        for record in records:
            print(record)
    else:
        logging.warning("Zone transfer failed.")


if __name__ == "__main__":
    # Usage Examples:
    # python3 net-dns-zone-transfer-tester.py example.com ns1.example.com
    # python3 net-dns-zone-transfer-tester.py example.com ns1.example.com -t
    # python3 net-dns-zone-transfer-tester.py example.com ns1.example.com -p 5353 -v
    main()