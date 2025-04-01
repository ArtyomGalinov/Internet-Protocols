import subprocess
import re
import json
import requests
import sys
import argparse


def load_config(config_file="config.json"):
    try:
        with open(config_file, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: configuration file {config_file} not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Incorrect configuration file {config_file}.")
        sys.exit(1)


def run_traceroute(target):
    try:
        command = ["tracert", target]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error while executing trace: {e}")
        sys.exit(1)


def extract_ips(traceroute_output):
    ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")  # re for ip-addresses
    return ip_pattern.findall(traceroute_output)


def get_as_info(ip):
    config = load_config()
    if not config["use_external_api"]:
        return "Unknown", "Unknown", "Unknown"  # if we are not using ipinfo.io

    url = config["whois_api"].format(ip=ip)
    try:
        response = requests.get(url, timeout=5)
        data = response.json()

        as_number = data.get("asn", "Unknown")  # AS
        if as_number == "Unknown":
            org_info = data.get("org", "")
            if "AS" in org_info:
                as_number = re.search(r'AS(\d+)', org_info)
                as_number = as_number.group(1) if as_number else "Unknown"

        country = data.get("country", "Unknown")  # country
        provider = data.get("org", "Unknown")  # provider

        return as_number, country, provider
    except requests.RequestException:
        return "Unknown", "Unknown", "Unknown"


def main():
    parser = argparse.ArgumentParser(description="Trace route with AS definitions")
    parser.add_argument("target", help="Domain name or IP address")

    args = parser.parse_args()
    target = args.target

    print("Tracing in progress...")
    traceroute_output = run_traceroute(target)

    print("Analyzing the route...")
    ips = extract_ips(traceroute_output)

    print("\nResult:")
    print("{:<5} {:<15} {:<10} {:<15} {:<20}".format("№", "IP", "AS", "Country", "Provider"))
    print("-" * 65)

    for index, ip in enumerate(ips, start=1):
        as_number, country, provider = get_as_info(ip)
        print(f"{index:<5} {ip:<15} {as_number:<10} {country:<15} {provider:<20}")


if __name__ == "__main__":
    main()
