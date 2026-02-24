# sweep

External attack surface recon. Subdomains, DNS, ports, HTTP, tech fingerprinting. Single binary.

Built by [VulnVerified](https://vulnverified.com) — continuous security monitoring with verified exploits.

## Install

```
go install github.com/vulnverified/sweep/cmd/sweep@latest
```

Or download from [releases](https://github.com/vulnverified/sweep/releases).

## Usage

```
sweep example.com
sweep example.com --json
sweep example.com --ports 80,443,8080
sweep example.com --concurrency 50 --timeout 1s
sweep example.com --axfr -v
sweep example.com --silent
```

## What it runs

1. Subdomain enumeration (4 passive sources + optional zone transfer)
   - crt.sh Certificate Transparency logs
   - DNS brute-force (~1500 common prefixes)
   - HackerTarget API
   - AlienVault OTX passive DNS
   - DNS zone transfer / AXFR (opt-in via `--axfr`)
2. DNS resolution + dangling CNAME detection
3. TCP connect port scan (top 100 ports default)
4. HTTP probing (status, title, server header)
5. Tech fingerprinting (~50 rules: servers, frameworks, CMS, CDN/WAF)

## Flags

| Flag | Default | |
|------|---------|---|
| `--json` | false | JSON to stdout |
| `--ports` | top 100 | Comma-separated ports |
| `--timeout` | 2s | Per-connection timeout |
| `--concurrency` | 25 | Max concurrent connections |
| `--axfr` | false | Test for DNS zone transfers |
| `--no-color` | false | Disable colors (respects `NO_COLOR`) |
| `--silent` | false | Results only |
| `-v` | false | Verbose |

## JSON

`--json` writes structured JSON to stdout, progress to stderr. Pipe-safe.

```json
{
  "target": "example.com",
  "duration_secs": 42.7,
  "subdomains": [{"host": "www.example.com", "sources": ["crt.sh", "brute", "hackertarget"]}],
  "dns_records": [{"host": "www.example.com", "ips": ["1.2.3.4"]}],
  "open_ports": [{"host": "www.example.com", "ip": "1.2.3.4", "port": 443}],
  "http_services": [{
    "url": "https://www.example.com:443",
    "status_code": 200,
    "title": "Example",
    "technologies": [{"name": "nginx", "category": "web-server"}]
  }],
  "dangling_cnames": [{"host": "old.example.com", "cname": "old.herokuapp.com", "status": "NXDOMAIN"}],
  "zone_transfers": [{"nameserver": "ns1.example.com", "success": true, "records": 42}],
  "warnings": ["hackertarget: API count exceeded"],
  "summary": {"subdomains_found": 23, "live_hosts": 19, "open_port_count": 47, "zone_transfers": 1}
}
```

## Notes

- TCP connect scan — no raw sockets, no root required, but detectable
- HackerTarget free tier: 100 queries/day. Rate limit degrades gracefully (warning, not failure).
- Only scan targets you own or have authorization to test
- User-Agent: `sweep/<version> (+https://github.com/vulnverified/sweep)`

## What's actually exploitable?

sweep maps your attack surface — subdomains, open ports, exposed services, technologies.
VulnVerified goes further: continuous monitoring, real exploitation testing, zero false positives.

→ [vulnverified.com](https://vulnverified.com)

## License

MIT
