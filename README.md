# Wayback Sensitive Finder


## 📦 Features

- Collects archived URLs from the Wayback Machine for a given domain and time range
- Filters for sensitive file extensions (e.g. `.bak`, `.env`, `.zip`, `.sql`, etc.)
- Supports custom keyword matching (e.g. `password`, `backup`, `employee`)
- Checks if those files are:
  - Available in archive (Wayback)
  - Still live on the target
- Outputs results **as they are found** (no delay)

## Usage

```bash
python3 wayback_sensitive_finder.py -u <domain> -m <from-to> -o <output_file> [-k <keywords>]
```

### Example:
```bash
python3 wayback_sensitive_finder.py -u adidas.co.uk -m 20190101-20220101 -o results.txt -k "password,employee,backup"
```

## Tip

Use longer time ranges (e.g. 20080101–20240101) to find old exposures. Combine this tool with other recon methods for maximum coverage.

## Output

Results are saved like:
```
[ARCHIVED FOUND] https://web.archive.org/web/.../config.php.bak
[LIVE FOUND] https://example.com/.env
```
