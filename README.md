# recon-ip

**IP threat intelligence**

Look up any IP address and find out who is behind it: whether it's a **VPN, proxy, Tor exit, datacenter** or a **real home or mobile connection**, and whether it has a **history of attacks or abuse**. Every verdict shows the evidence behind it.

recon-ip runs on your own computer and opens in your browser. No account needed.

---

## What you get

- **Two clear verdicts**: what kind of connection the IP is, and its threat history, scored separately.
- **Infrastructure history**: who has operated the IP's network and for how long. New or frequently resold networks are a common sign of attack infrastructure.
- **Neighborhood scan**: the 256 surrounding addresses shown as a colored grid, exposing risky networks.
- **Analyst assessment**: a plain-English summary with a recommended action.

**Sources:** AbuseIPDB, GreyNoise, Shodan InternetDB, Spamhaus, SpamCop, DroneBL, the Tor Project, RIPEstat and ip-api.

---

## Install and run

### 1. Install Python

You need **Python 3.8 or newer**. Check with:

```
python --version
```

If that fails, download Python from **https://www.python.org/downloads/**.
On Windows, tick **"Add python.exe to PATH"** on the first installer screen.

> On macOS and Linux, use `python3` instead of `python` in every command below.

### 2. Download recon-ip

Click the green **Code** button at the top of this page, choose **Download ZIP**, and extract it.

Or, with Git:

```
git clone https://github.com/dev3lr/reconip.git
```

### 3. Add your AbuseIPDB key (recommended, free)

This adds attack-report history to every lookup. recon-ip works without it, but the threat verdict is less complete.

1. Create a free account at **https://www.abuseipdb.com/register**.
2. Go to **Account → API** and create a key.
3. In the recon-ip folder, create a file named **`.env`** containing this one line (with your key after the `=`):

   ```
   ABUSEIPDB_API_KEY=paste_your_key_here
   ```

   **Windows tip:** in Notepad, choose *Save as*, set *Save as type* to **All files**, and name it `.env`.

Keep this file private. Never share it or upload it anywhere.

### 4. Start recon-ip

Open a terminal **in the recon-ip folder**
(Windows: open the folder, click the address bar, type `cmd` and press Enter) and run:

```
python server.py
```

### 5. Open it

Go to **http://localhost:8000** in your browser and look up any IP.

To stop recon-ip, press **Ctrl + C** in the terminal.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` is not recognized | Reinstall Python and tick **Add python.exe to PATH**, or try `py server.py` |
| Port 8000 is already in use | Use another port. Windows: `set PORT=8080 && python server.py` · macOS/Linux: `PORT=8080 python3 server.py`, then open http://localhost:8080 |
| No AbuseIPDB row in results | Check the `.env` file is in the same folder as `server.py`, is named exactly `.env` (not `.env.txt`), then restart |
| A lookup is slow the first time | Normal: nine sources are queried at once. Repeat lookups are cached |

---

## Command-line use

Prefer the terminal? Look up IPs directly:

```
python ipcheck.py 8.8.8.8
python ipcheck.py 1.1.1.1 example.com
python ipcheck.py --json 8.8.8.8
```

---

## Optional settings

Add any of these to your `.env` file:

| Setting | What it does |
|---|---|
| `ABUSEIPDB_API_KEY` | Adds attack-report history (recommended) |
| `ANTHROPIC_API_KEY` | AI-written analyst assessment instead of the rule-based one. Requires `pip install anthropic`. Paid per use |
| `AI_DAILY_LIMIT` | Max AI-written assessments per day (default 200) |
| `PORT` | Port to run on (default 8000) |
| `RATE_LIMIT` | Requests per visitor per minute (default 45) |

---

## Good to know

- The free data sources have limits: ip-api allows about 45 lookups a minute and is for non-commercial use; AbuseIPDB's free plan allows 1,000 lookups a day.
- Residential proxy services route traffic through real home connections, so they can look like ordinary home users.
- Results are automated assessments from third-party data and can be wrong. Use recon-ip for lawful purposes only, and never to harass or target individuals.
