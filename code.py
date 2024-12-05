import re
import csv
from collections import Counter, defaultdict

# Constants
LOG_FILE = 'sample.log'
FAILED_LOGIN_THRESHOLD = 10
CSV_FILE = 'result.csv'

def parse_log_file(file_path):
    # Reads the log file and returns all its lines
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []

def extract_ip_requests(lines):
    # Extracts IP addresses and counts requests per IP
    ip_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
    ip_counts = Counter(ip_pattern.search(line).group(1) for line in lines if ip_pattern.search(line))
    return ip_counts

def extract_endpoints(lines):
    # Extracts endpoints and counts their accesses
    endpoint_pattern = re.compile(r'\"[A-Z]+\s(\/\S*)\sHTTP\/\d+\.\d+')
    endpoint_counts = Counter(endpoint_pattern.search(line).group(1) for line in lines if endpoint_pattern.search(line))
    return endpoint_counts

def detect_suspicious_activity(lines):
    # Detects IP addresses with excessive failed login attempts.
    failed_login_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).*?(401|Invalid credentials)')
    failed_logins = Counter(failed_login_pattern.search(line).group(1) for line in lines if failed_login_pattern.search(line))
    return {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips):
    # Saves analysis results to a CSV file
    with open(CSV_FILE, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        writer.writerow([])

        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([])

        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def display_results(ip_requests, most_accessed_endpoint, suspicious_ips):
    # Displays analysis results in the terminal
    print("\nRequests per IP:")
    print(f"{'IP Address':<20}{'Request Count':<15}")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20}{count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Count':<15}")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20}{count:<15}")

def main():

    # Parse log file
    lines = parse_log_file(LOG_FILE)
    if not lines:
        return

    # Perform analysis
    ip_requests = extract_ip_requests(lines)
    endpoints = extract_endpoints(lines)
    most_accessed_endpoint = endpoints.most_common(1)[0] if endpoints else ('None', 0)
    suspicious_ips = detect_suspicious_activity(lines)

    # Output results
    display_results(ip_requests, most_accessed_endpoint, suspicious_ips)
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips)

    print(f"\nAnalysis complete. Results saved to '{CSV_FILE}'.")

if __name__ == "__main__":
    main()
