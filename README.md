# recon-ip

**IP threat intelligence**

Look up any IP or hostname: location, ISP, whether it's a **VPN / proxy / Tor / datacenter**
or a **real home or mobile connection**, and whether it has a **history of attacks or abuse**.

Beyond a normal lookup it also shows:
- **Infrastructure history**: who has routed the IP's block on the internet and since when (RIPEstat BGP data).
  Freshly announced or frequently re-leased blocks are a classic sign of attack infrastructure.
- **Neighborhood scan**: all 256 addresses of the surrounding /24 as a colored grid (Tor, blocklisted, VPN, datacenter, home).
- **Analyst assessment**: a plain-English summary and recommended action. Rule-based by default, or written by
  Claude when `ANTHROPIC_API_KEY` is set.

Works as a website (`server.py`) or a command-line tool (`ipcheck.py`). Python 3.8+.
The only optional dependency is `anthropic`, for the AI-written assessment.

## Run it locally

```
python server.py
```
Open http://localhost:8000.

## Put it online (free) with Render

1. Push this folder to a GitHub repository.
2. Go to https://dashboard.render.com, choose **New > Blueprint**, pick the repository.
   Render reads `render.yaml` and sets everything up.
3. Optional: paste a free AbuseIPDB key (https://www.abuseipdb.com/register) when asked for
   `ABUSEIPDB_API_KEY`. That adds attack-report history.
4. You'll get a URL like `https://ipcheck-xxxx.onrender.com` to share.

The free plan sleeps after 15 minutes idle, so the first visit after a while takes ~30 seconds.

### Other hosts
- **Railway / Fly.io / any VPS**: use the `Dockerfile`. Set `TRUST_PROXY=1` when behind a proxy
  so "Check my IP" and the rate limit see the visitor's real IP.

## Settings (environment variables)

| Variable | Meaning |
|---|---|
| `PORT` | Port to listen on (default 8000; hosts set this automatically) |
| `ABUSEIPDB_API_KEY` | Enables abuse report history and ISP usage type |
| `ANTHROPIC_API_KEY` | Enables the Claude-written analyst assessment (otherwise rule-based) |
| `IPCHECK_AI_MODEL` | Claude model for the assessment (default `claude-opus-5-5`) |
| `TRUST_PROXY` | Number of reverse proxies in front of the app (`1` on Render/Railway/Fly). Leave unset otherwise |
| `AI_DAILY_LIMIT` | Max Claude-written reports per day (default 200) |
| `RATE_LIMIT` | API calls per visitor per minute (default 45; one page lookup uses 3) |

Lookups are cached for 15 minutes per IP, neighborhood scans for an hour per /24.

## Limits
- ip-api.com's free tier allows ~45 lookups/minute **for the whole server** and is for
  non-commercial use only. GreyNoise's free API has a daily cap.
- Residential-proxy services route traffic through real home connections, so they look
  residential. Detecting those needs a paid feed (IPQualityScore, Spur, etc).

## Command line
```
python ipcheck.py 8.8.8.8 example.com
python ipcheck.py --json 1.2.3.4
```
