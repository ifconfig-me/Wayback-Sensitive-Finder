import argparse
import requests
import re
from urllib.parse import quote
from datetime import datetime

sensitive_extensions = re.compile(r'\.(bak|old|zip|tar|gz|7z|sql|env|git|conf|log|inc|swp|save|tmp|cache|backup|ini|db)$', re.IGNORECASE) #add more extensions here..

def fetch_wayback_urls(domain, from_date, to_date):
    print(f"[*] Fetching Wayback Machine URLs for: {domain} from {from_date} to {to_date}")
    url = (
        f"https://web.archive.org/cdx/search/cdx?url=*.{quote(domain)}/*"
        f"&output=text&fl=original&collapse=urlkey&from={from_date}&to={to_date}"
    )
    response = requests.get(url)
    if response.status_code != 200:
        print("[!] Failed to fetch from Wayback Machine")
        return []
    return list(set(filter(None, response.text.splitlines())))

def filter_sensitive_files(urls):
    print("[*] Filtering for sensitive file extensions")
    return [url for url in urls if sensitive_extensions.search(url)]

def filter_keywords(urls, keyword_list):
    print("[*] Filtering URLs by sensitive keywords")
    keyword_pattern = re.compile("|".join(re.escape(k) for k in keyword_list), re.IGNORECASE)
    return [url for url in urls if keyword_pattern.search(url)]

def check_archived_availability(urls, output_file):
    found_archives = []
    with open(output_file, "a") as f:
        for url in urls:
            print(f"[*] Checking archived snapshot for: {url}")
            try:
                response = requests.get(
                    f"http://archive.org/wayback/available?url={quote(url)}", timeout=10
                )
                data = response.json()
                snapshot = data.get("archived_snapshots", {}).get("closest", {}).get("url")
                if snapshot:
                    found_archives.append(snapshot)
                    f.write(f"[ARCHIVED FOUND] {snapshot}\n")
            except Exception as e:
                print(f"[!] Error checking snapshot for {url}: {e}")
    return found_archives

def check_live_availability(urls, output_file):
    found_live = []
    with open(output_file, "a") as f:
        for url in urls:
            print(f"[*] Checking live availability for: {url}")
            try:
                response = requests.head(url, timeout=10)
                if response.status_code == 200:
                    found_live.append(url)
                    f.write(f"[LIVE FOUND] {url}\n")
            except Exception as e:
                print(f"[!] Error checking live URL {url}: {e}")
    return found_live

def main():
    parser = argparse.ArgumentParser(description="Wayback Sensitive File Finder")
    parser.add_argument("-u", "--url", required=True, help="Target domain")
    parser.add_argument("-m", "--period", required=True, help="Time period in the format FROM-TO (e.g. 20190101-20211231)")
    parser.add_argument("-o", "--output", required=True, help="Output filename")
    parser.add_argument("-k", "--keywords", help="Comma-separated keywords to look for in URLs")
    args = parser.parse_args()

    if '-' not in args.period:
        print("[!] Period e.g., 20190101-20211231")
        return

    from_date, to_date = args.period.split('-')
    keyword_list = [k.strip() for k in args.keywords.split(',')] if args.keywords else []

    with open(args.output, "w") as f:
        f.write(f"Scan Date: {datetime.now()}\n\n")

    all_urls = fetch_wayback_urls(args.url, from_date, to_date)
    sensitive_urls = filter_sensitive_files(all_urls)
    keyword_urls = filter_keywords(all_urls, keyword_list) if keyword_list else []
    combined_urls = list(set(sensitive_urls + keyword_urls))

    archived = check_archived_availability(combined_urls, args.output)
    live = check_live_availability(combined_urls, args.output)

    print(f"\n[+] Scan completed. Results saved to {args.output}")

if __name__ == "__main__":
    main()
