from socket import timeout
from ssl import SSLError
from urllib.error import URLError
import httpx
import argparse
import rich
from rich.console import Console
from urllib.parse import urlparse, parse_qsl, urlencode

# Rich Console
console = Console()

# Argument Parser
parser = argparse.ArgumentParser()

parser.add_argument('-l', '--list', help='To provide list of URLs as an input')
parser.add_argument('-u', '--url', help='To provide single URL as an input')
parser.add_argument('-p', '--payloads', help='To provide payload file having Blind SQL Payloads', required=True)
parser.add_argument('-v', '--verbose', help='Run on verbose mode', action='store_true')
parser.add_argument('-a', '--approve', help='Pause and wait for approval if a vulnerability is found', action='store_true')
args = parser.parse_args()

# Open a file to save vulnerable URLs
vulnerable_file = open('vulnerable_urls.txt', 'a')

# Load payloads from the file
try:
    with open(args.payloads, 'r') as file:
        payloads = [line.strip() for line in file]
except FileNotFoundError as e:
    console.print(f"[bold red]Error: {e}[/]")
    exit()
except IOError as e:
    console.print(f"[bold red]Error: {e}[/]")
    exit()

# Function to handle vulnerabilities found
def handle_vulnerability(url, param, payload, res_time):
    console.print(f"🌐 [bold][cyan]Testing for URL: {url}[/]")
    console.print(f"💉 [bold][cyan]Parameter: {param}, Payload: {payload}[/]")
    console.print(f"⏱️ [bold][cyan]Response Time: {res_time}[/]")
    console.print("🐞 [bold][red]Status: Vulnerable[/]")
    
    # Save the vulnerable URL and payload to the file
    try:
        vulnerable_file.write(f"{url} - Parameter: {param} - Payload: {payload} - Response Time: {res_time}\n")
        vulnerable_file.flush()  # Ensure the data is written to the file immediately
    except IOError as e:
        console.print(f"[bold red]Error writing to file: {e}[/]")

    # Pause for approval if required
    if args.approve:
        input("Press ENTER to continue...")

# Function to test each URL with payloads in parameters
def test_url_with_payloads(url):
    parsed_url = urlparse(url)
    query_params = dict(parse_qsl(parsed_url.query))

    for param in query_params:
        original_value = query_params[param]
        param_vulnerable = False  # Flag to check if the parameter is vulnerable

        for payload in payloads:
            if param_vulnerable:  # Skip the rest of the payloads if already vulnerable
                break

            # Modify the parameter with the payload
            query_params[param] = payload
            modified_query = urlencode(query_params)
            modified_url = parsed_url._replace(query=modified_query).geturl()

            try:
                with httpx.Client(timeout=60) as client:
                    response = client.get(modified_url, follow_redirects=True)
                res_time = response.elapsed.total_seconds()

                if 25 <= res_time <= 50:
                    handle_vulnerability(modified_url, param, payload, res_time)
                    param_vulnerable = True  # Mark the parameter as vulnerable
            except (httpx.RequestError, timeout, SSLError, URLError) as e:
                console.print(f"[bold red]Error: {e}[/]")
                break

            # Restore the original value for the next iteration
            query_params[param] = original_value

# Function to process multiple URLs from file
def process_urls_from_file():
    try:
        with open(args.list, 'r') as file:
            urls = [line.strip() for line in file]

        for url in urls:
            if args.verbose:
                console.print(f"🌐 [bold][cyan]Testing URL: {url}[/]")
            test_url_with_payloads(url)

    except FileNotFoundError as e:
        console.print(f"[bold red]Error: {e}[/]")
        exit()
    except IOError as e:
        console.print(f"[bold red]Error: {e}[/]")
        exit()

# Main logic
if args.url:
    if args.verbose:
        console.print(f"🌐 [bold][cyan]Testing single URL: {args.url}[/]")
    test_url_with_payloads(args.url)
elif args.list:
    process_urls_from_file()
else:
    console.print("[bold red]Error: Either -u or -l flag is required[/]")

# Close the vulnerable file after the script finishes
vulnerable_file.close()
