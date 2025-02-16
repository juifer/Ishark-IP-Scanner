import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from colorama import init, Fore
import shutil
import struct

# Initialize colorama
init(autoreset=True)

# ASCII Art
ascii_art = '''
 ▄█     ▄████████    ▄█    █▄       ▄████████    ▄████████    ▄█   ▄█▄ 
███    ███    ███   ███    ███     ███    ███   ███    ███   ███ ▄███▀ 
███▌   ███    █▀    ███    ███     ███    ███   ███    ███   ███▐██▀   
███▌   ███         ▄███▄▄▄▄███▄▄   ███    ███  ▄███▄▄▄▄██▀  ▄█████▀    
███▌ ▀███████████ ▀▀███▀▀▀▀███▀  ▀███████████ ▀▀███▀▀▀▀▀   ▀▀█████▄    
███           ███   ███    ███     ███    ███ ▀███████████   ███▐██▄   
███     ▄█    ███   ███    ███     ███    ███   ███    ███   ███ ▀███▄ 
█▀    ▄████████▀    ███    █▀      ███    █▀    ███    ███   ███   ▀█▀ 
                                                ███    ███   ▀         
'''

second_ascii_art = '''
            ██████ ▄████▄  ▄▄▄      ███▄    █ ███▄    █▓█████ ██▀███            
          ▒██    ▒▒██▀ ▀█ ▒████▄    ██ ▀█   █ ██ ▀█   █▓█   ▀▓██ ▒ ██▒          
          ░ ▓██▄  ▒▓█    ▄▒██  ▀█▄ ▓██  ▀█ ██▓██  ▀█ ██▒███  ▓██ ░▄█ ▒          
            ▒   ██▒▓▓▄ ▄██░██▄▄▄▄██▓██▒  ▐▌██▓██▒  ▐▌██▒▓█  ▄▒██▀▀█▄            
          ▒██████▒▒ ▓███▀ ░▓█   ▓██▒██░   ▓██▒██░   ▓██░▒████░██▓ ▒██▒          
          ▒ ▒▓▒ ▒ ░ ░▒ ▒  ░▒▒   ▓▒█░ ▒░   ▒ ▒░ ▒░   ▒ ▒░░ ▒░ ░ ▒▓ ░▒▓░          
          ░ ░▒  ░ ░ ░  ▒    ▒   ▒▒ ░ ░░   ░ ▒░ ░░   ░ ▒░░ ░  ░ ░▒ ░ ▒░          
          ░  ░  ░ ░         ░   ▒     ░   ░ ░   ░   ░ ░   ░    ░░   ░           
                ░ ░ ░           ░  ░        ░         ░   ░  ░  ░                
                 ░                                                               
    Project coded by JUIFER
'''


def center_text(text):
    """Centers the given text."""
    terminal_width = shutil.get_terminal_size().columns
    lines = text.split('\n')
    return "\n".join(line.center(terminal_width) for line in lines)


def ip_to_int(ip):
    """Converts an IP address to a 32-bit integer."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(ip_int):
    """Converts a 32-bit integer to an IP address."""
    return socket.inet_ntoa(struct.pack("!I", ip_int))


def calculate_total_ips(start_ip, end_ip):
    """Calculates the total number of IPs between two IPs."""
    return ip_to_int(end_ip) - ip_to_int(start_ip) + 1


def scan_ip(ip, port, timeout):
    """Attempt to connect to the given IP and port. Returns IP:Port if successful."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                return f"{ip}:{port}"
    except socket.error:
        pass
    return None


def scan_proxies_from_file(filename, port, threads, timeout, batch_size=10000):
    """
    Scans each IP range separately and shows progress for each range from 0% to 100%.
    Batching is used to avoid memory issues on huge ranges.
    """
    timeout = float(timeout)
    output_file = "open_ips.txt"
    open_ips = []

    # Read and parse the IP ranges from file
    with open(filename, 'r') as file:
        ranges = [line.strip().split('-') for line in file if line.strip()]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for range_index, (start_ip, end_ip) in enumerate(ranges, start=1):
            start_int = ip_to_int(start_ip)
            end_int = ip_to_int(end_ip)
            total_range_ips = end_int - start_int + 1
            range_scanned = 0
            print(f"\nScanning range {range_index}: {start_ip} to {end_ip}")

            # Process the current range in batches
            for batch_start in range(start_int, end_int + 1, batch_size):
                batch_end = min(batch_start + batch_size - 1, end_int)
                futures = {}
                for ip_int in range(batch_start, batch_end + 1):
                    ip_str = int_to_ip(ip_int)
                    futures[executor.submit(scan_ip, ip_str, port, timeout)] = ip_str

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        open_ips.append(result)
                        with open(output_file, 'a') as f:
                            f.write(result + "\n")
                    range_scanned += 1
                    percent_done = (range_scanned / total_range_ips) * 100
                    sys.stdout.write(
                        f"\rRange {range_index} progress: {range_scanned}/{total_range_ips} "
                        f"({percent_done:.2f}%) - Found {len(open_ips)} open IPs"
                    )
                    sys.stdout.flush()
            print(f"\nFinished scanning range {range_index}.")
    print(f"\nScanning complete. Found {len(open_ips)} open IPs.")


def main():
    print(Fore.YELLOW + center_text(ascii_art))
    print(Fore.RED + center_text(second_ascii_art))
    filename = input("Enter the filename containing IP ranges (format: IP-IP, one per line): ")
    port = int(input("Enter the port to scan: "))
    threads = int(input("Enter the number of threads to use: "))
    timeout = float(input("Enter the timeout value (between 0.5 and 3.0): "))
    scan_proxies_from_file(filename, port, threads, timeout)


if __name__ == "__main__":
    main()
