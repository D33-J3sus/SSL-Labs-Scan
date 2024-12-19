import requests
import time
import csv

# SSL Labs API Endpoint
API_URL = "https://api.ssllabs.com/api/v3/analyze"
ENDPOINT_DATA_URL = "https://api.ssllabs.com/api/v3/getEndpointData"

def scan_domain(domain):
    """This function interacts with the SSL Labs API to scan a given domain and retrieve the results."""
    print(f"Initiating scan for domain: {domain}")
    params = {
        "host": domain,
        "publish": "off",
        "startNew": "on",
        "all": "on",
        "ignoreMismatch": "on",
    }
    # Sends a GET request to SSL Labs API with params, then checks if the request was successful (200) if not, log error and exit.
    response = requests.get(API_URL, params=params)
    if response.status_code != 200:
        print("Failed to initiate scan.")
        print("Response:", response.text)
        return None

    data = response.json()
    print(data)
    if data.get("status") in ["ERROR"]:
        print("Error in API response:", data)
        return None

    # Repeat queries to check scan status, sleep for 10 seconds between retries.
    while data.get("status") in ["DNS", "IN_PROGRESS"]:
        print("Scan in progress. Waiting 10 seconds before retrying...")
        time.sleep(10)
        response = requests.get(API_URL, params={"host": domain})
        data = response.json()
    return data

def get_endpoint_data(host, ip):
    '''Fetch endpoint data for specific endpoint using the hostname for vulnerability information.'''
    params = {
    "host":host,
    "s":ip,
    }
    response = requests.get(ENDPOINT_DATA_URL, params=params)
    print(response)
    if response.status_code != 200:
        print(f"Failed to get endpoint data for endpoint {host}")
        return None
    return response.json()

def write_to_csv(data_list, filename="scan_results.csv"):
    """This function writes scan results for all domains into a CSV file."""
    print(f"Writing results to {filename}")
    headers = [
        "host", "status", "startTime", "testTime", "duration", "ipAddress", "serverName", "grade", "hasWarnings", "isExceptional", "forwardSecracy", "vulnBEAST","supportsRc4", "heartbleed", "openSslCcs", "openSSLLuckyMinus20", "ticketbleed", "bleichenbacher", 
        "zombiePoodle", "goldenDoodle", "zeroLengthPaddingOracle", "sleepingPoodle", "poodle", "poodleTls", "freak",         
    ]

    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        for data in data_list:
            endpoints = data.get("endpoints", [])

            for endpoint in endpoints:
                '''Fetch detailed endpoint data form getEndpointData'''
                host = data.get("host")
                ip = endpoint.get("ipAddress")
                endpoint_details = get_endpoint_data(host, ip)

                if endpoint_details:
                    details = endpoint_details.get("details", {})
                    certchain = endpoint_details.get("certChains", {})

                writer.writerow([
                    data.get("host"),
                    data.get("status"),
                    data.get("startTime"),
                    data.get("testTime"),
                    endpoint.get("duration"),
                    endpoint.get("ipAddress"),
                    endpoint.get("serverName"),
                    endpoint.get("grade"),
                    endpoint.get("hasWarnings"),
                    endpoint.get("isExceptional"),
                    details.get("forwardSecracy"),
                    details.get("vulnBEAST"),
                    details.get("supportsRc4"),
                    details.get("heartbleed"),
                    details.get("openSslCcs"),
                    details.get("openSSLLuckyMinus20"),
                    details.get("ticketbleed"),
                    details.get("bleichenbacher"),
                    details.get("zombiePoodle"),
                    details.get("goldenDoodle"),
                    details.get("zeroLengthPaddingOracle"),
                    details.get("sleepingPoodle"),
                    details.get("poodle"),
                    details.get("poodleTls"),
                    details.get("freak"),
                ])

if __name__ == "__main__":
    domains = [
"google.com"
]
    results = []

    for domain in domains:
        scan_result = scan_domain(domain)
        if scan_result:
            results.append(scan_result)

    if results:
        write_to_csv(results)
        print("Scan complete. Results saved to scan_results.csv.")
    else:
        print("No scans were successful.")

