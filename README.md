# Proxy Dupper

Language: **English** | [Русский](readme-ru.md)

Proxy Dupper takes a list of authenticated proxies, groups them by /24 network, generates all IPs in each /24, checks them, and saves the valid ones.

## Requirements
- Python 3.10+
- Internet access (for proxy checks)

## Install (uv)
```bash
uv venv
uv sync
```

## Install (pip)
```bash
python -m venv .venv
.venv\\Scripts\\Activate.ps1
pip install -e .
```

## Prepare Input
Create a file like `proxies.txt` with one proxy per line:
```
login:password@1.2.3.4:8080
```

## Run
```bash
python main.py -i proxies.txt -o valid.txt -p http -w 20 -t 8 --test-url http://httpbin.org/ip
```

## Output
Valid proxies are written to the output file specified by `-o`.

## CLI Options
- `-i, --input` Path to input proxies file (required)
- `-o, --output` Output file for valid proxies (required)
- `-p, --protocol` `http` or `socks5` (default: `http`)
- `-w, --workers` Async concurrency limit (default: `10`)
- `-t, --timeout` Request timeout in seconds (default: `8`)
- `--test-url` URL to test proxy connectivity (default: `http://httpbin.org/ip`)

## Notes
- If the input file contains multiple proxies from the same /24, only the first one is used to generate candidates.
- The checker sends a request to `http://httpbin.org/ip`.
