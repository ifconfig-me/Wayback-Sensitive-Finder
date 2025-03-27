import argparse
import requests
import re
from urllib.parse import quote
from datetime import datetime

sensitive_extensions = re.compile(r'\.(bak|old|zip|tar|gz|7z|sql|env|git|conf|log|inc|swp|save|tmp|cache|backup|ini|db)$', re.IGNORECASE)
ignore_extensions = re.compile(r'\.([a-z0-9]+)(\?.*)?$', re.IGNORECASE)
ignore_filetypes = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp', 'ico', 'tiff', 'woff', 'woff2', 'eot', 'ttf', 'otf', 'js', 'css'}
ignore_keywords = {'robots.txt'}

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
    urls = list(set(filter(None, response.text.splitlines())))

    def is_static(u):
        match = re.search(ignore_extensions, u.split('?')[0])
        ext = match.group(1).lower() if match else ""
        return ext in ignore_filetypes or any(keyword in u.lower() for keyword in ignore_keywords)

    filtered_urls = [url for url in urls if not is_static(url)]
    print(f"[+] Retrieved {len(urls)} total URLs from archive.")
    print(f"[+] {len(filtered_urls)} URLs remaining after ignoring static filetypes and robots.txt.")
    with open("raw-urls.txt", "w") as debug_file:
        debug_file.write("\n".join(filtered_urls))
    return filtered_urls

def filter_sensitive_files(urls):
    print("[*] Filtering for sensitive file extensions")
    results = [url for url in urls if sensitive_extensions.search(url)]
    print(f"[+] {len(results)} matched sensitive file extensions")
    return results

def filter_keywords(urls, keyword_list):
    print("[*] Filtering URLs by sensitive keywords")
    keyword_pattern = re.compile("|".join(re.escape(k) for k in keyword_list), re.IGNORECASE)
    results = [url for url in urls if keyword_pattern.search(url)]
    print(f"[+] {len(results)} matched keywords")
    return results

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
    parser.add_argument("-u", "--url", required=True, help="Target domain name")
    parser.add_argument("-m", "--period", required=True, help="Time period in format FROM-TO (e.g. 20190101-20211231)")
    parser.add_argument("-o", "--output", required=True, help="Output filename")
    parser.add_argument("-k", "--keywords", help="Comma-separated keywords to look for in URLs")
    parser.add_argument("--no-filter", action="store_true", help="Disable filtering and check all Wayback URLs")
    args = parser.parse_args()

    if '-' not in args.period:
        print("[!] Period must be in format FROM-TO, e.g., 20190101-20211231")
        return

    from_date, to_date = args.period.split('-')
    keyword_list = [k.strip() for k in args.keywords.split(',')] if args.keywords else []

    with open(args.output, "w") as f:
        f.write(f"Scan Date: {datetime.now()}\n\n")

    all_urls = fetch_wayback_urls(args.url, from_date, to_date)
    if not all_urls:
        print("[!] No URLs found in Wayback Machine for given period and domain.")
        return

    if args.no_filter:
        combined_urls = all_urls
        print("[*] Filtering disabled. Scanning all retrieved URLs.")
    else:
        sensitive_urls = filter_sensitive_files(all_urls)
        keyword_urls = filter_keywords(all_urls, keyword_list) if keyword_list else []
        combined_urls = list(set(sensitive_urls + keyword_urls))

    if not combined_urls:
        print("[!] No URLs matched the filters. Try adjusting keywords or enabling --no-filter.")
        return

    archived = check_archived_availability(combined_urls, args.output)
    live = check_live_availability(combined_urls, args.output)

    print(f"\n[+] Scan completed. Results saved to {args.output}")

if __name__ == "__main__":
    main()
