from socket import timeout, gethostbyname, gaierror
from ssl import SSLError
from urllib.error import URLError
import httpx
import argparse
import rich
from rich.console import Console
from urllib.parse import urlparse, parse_qsl, urlencode

console = Console()

parser = argparse.ArgumentParser(description='Test URLs for vulnerabilities using provided payloads.')

parser.add_argument('-l', '--list', help='File containing list of URLs to test.')
parser.add_argument('-u', '--url', help='Single URL to test.')
parser.add_argument('-p', '--payloads', help='File containing Blind SQL Injection payloads.', required=True)
parser.add_argument('-v', '--verbose', help='Enable verbose mode.', action='store_true')
parser.add_argument('-a', '--approve', help='Pause for approval when a vulnerability is found.', action='store_true')
args = parser.parse_args()

vulnerable_file = open('vulnerable_urls.txt', 'a')

try:
    with open(args.payloads, 'r') as file:
        payloads = [line.strip() for line in file]
except FileNotFoundError as e:
    console.print(f"[bold red]Error: {e}[/]")
    exit()
except IOError as e:
    console.print(f"[bold red]Error: {e}[/]")
    exit()

def is_domain_resolvable(url):
    parsed_url = urlparse(url)
    try:
        host = parsed_url.netloc.split(':')[0]
        gethostbyname(host)
        return True
    except gaierror:
        return False

def handle_vulnerability(url, param, payload, res_time):
    if args.verbose:
        console.print(f"🌐 [bold][cyan]Testing for URL: {url}[/]")
        console.print(f"💉 [bold][cyan]Parameter: {param}, Payload: {payload}[/]")
        console.print(f"⏱️ [bold][cyan]Response Time: {res_time}[/]")
        console.print("🐞 [bold][red]Status: Vulnerable[/]")
    else:
        console.print(f"🐞 [bold][red]Vulnerable URL: {url} - Parameter: {param} - Payload: {payload} - Response Time: {res_time}[/]")
    
    try:
        vulnerable_file.write(f"{url} - Parameter: {param} - Payload: {payload} - Response Time: {res_time}\n")
        vulnerable_file.flush()  # Ensure the data is written to the file immediately
    except IOError as e:
        console.print(f"[bold red]Error writing to file: {e}[/]")

    if args.approve:
        input("Press ENTER to continue...")

def test_url_with_payloads(url):
    if not is_domain_resolvable(url):
        console.print(f"[bold red]Skipping URL {url} as its domain cannot be resolved[/]")
        return

    parsed_url = urlparse(url)
    query_params = dict(parse_qsl(parsed_url.query))

    for param in query_params:
        original_value = query_params[param]
        param_vulnerable = False

        for payload in payloads:
            if param_vulnerable:
                break

            query_params[param] = payload
            modified_query = urlencode(query_params)
            modified_url = parsed_url._replace(query=modified_query).geturl()

            if args.verbose:
                console.print(f"[bold yellow]Testing Parameter: {param} with Payload: {payload}[/]")

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

            query_params[param] = original_value

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

if args.url:
    if args.verbose:
        console.print(f"🌐 [bold][cyan]Testing single URL: {args.url}[/]")
    test_url_with_payloads(args.url)
elif args.list:
    process_urls_from_file()
else:
    console.print("[bold red]Error: Either -u or -l flag is required[/]")

vulnerable_file.close()
