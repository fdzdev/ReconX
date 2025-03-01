#!/bin/bash

# === Input Files ===
INPUT_FILE="${1:-all_domains.txt}"
MASSCAN_RESULTS="1ip_ports.txt"
CLEANED_PORTS="ulti.txt"
NUCLEI_WEB_RESULTS="web_vulnerabilities.txt"
NUCLEI_DAST_RESULTS="dast_results.txt"
NUCLEI_INFRA_RESULTS="infra_vulnerabilities.txt"
TELEGRAM_BOT_TOKEN="7764159945:AAF8WdCx2bBObO5ASGJd0_zlBBah6IWhu5g"
TELEGRAM_CHAT_ID="6932389568"  # Replace with your actual Telegram Chat ID

# === 1️⃣ Validate Input File ===
if [ ! -f "$INPUT_FILE" ]; then
    echo "❌ Error: Input file '$INPUT_FILE' not found."
    exit 1
fi

# === 2️⃣ Run HTTPX to Enumerate Domains ===
echo "✅ Running httpx scan on $INPUT_FILE..."
httpx -sc -ip -server -title -wc -l "$INPUT_FILE" -o httpx.dom.txt

if [ ! -s httpx.dom.txt ]; then
    echo "❌ Error: httpx scan failed."
    exit 1
fi

# === 3️⃣ Categorize HTTP Responses ===
echo "✅ Extracting HTTP status categories..."
touch alive.txt redirects.txt errors.txt server_errors.txt IPS.dom.txt

(
  awk '/200/ {print $1}' httpx.dom.txt | sort -u > alive.txt &
  awk '/301|302/ {print $1}' httpx.dom.txt | sort -u > redirects.txt &
  awk '/400|403|404|405|429/ {print $1}' httpx.dom.txt | sort -u > errors.txt &
  awk '/500|502|503/ {print $1}' httpx.dom.txt | sort -u > server_errors.txt &
  grep -oE '\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]' httpx.dom.txt | tr -d '[]' | sort -u > IPS.dom.txt &
  wait
)

echo "✅ Alive: $(wc -l < alive.txt), Redirects: $(wc -l < redirects.txt), Errors: $(wc -l < errors.txt), Server Errors: $(wc -l < server_errors.txt), Unique IPs: $(wc -l < IPS.dom.txt)"

# === 4️⃣ Run Masscan on Unique IPs ===
if [ -s IPS.dom.txt ]; then
    echo "🚀 Running masscan..."
    sudo masscan -iL IPS.dom.txt --top-ports 100 --rate=1000 -oG "$MASSCAN_RESULTS"
fi

# === 5️⃣ Clean Masscan Results (Extract IP:PORT) ===
if [ -s "$MASSCAN_RESULTS" ]; then
    awk '/Host:/ && /Ports:/ {
        match($0, /Host: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/, ip);
        match($0, /Ports: ([0-9]+)/, port);
        if (ip[1] && port[1]) print ip[1] ":" port[1];
    }' "$MASSCAN_RESULTS" > "$CLEANED_PORTS"
    echo "✅ Cleaned IP:PORT list saved to $CLEANED_PORTS"
fi

# === 6️⃣ Run Nuclei for Vulnerability Detection ===
# === 6️⃣ Run Nuclei for Vulnerability Detection ===
if [ -s alive.txt ]; then
    echo "🚀 Running nuclei on alive URLs (Web CVEs)..."

    # Run DAST-specific scans separately
    nuclei -l alive.txt -t dast/ -o "$NUCLEI_DAST_RESULTS" -dast

    # Run standard vulnerability scans
    nuclei -l alive.txt -t takeovers/ -t cves/ -t exposures/ -t misconfiguration/ -o "$NUCLEI_WEB_RESULTS" -as &

fi

if [ -s "$CLEANED_PORTS" ]; then
    echo "🚀 Running nuclei on open IP:PORT (Network CVEs)..."
    nuclei -l "$CLEANED_PORTS" -t default-logins/ -t misconfig/ -o "$NUCLEI_INFRA_RESULTS" -as &
fi

wait  # Ensure all background processes complete

# === 7️⃣ Summarize Nuclei Results ===
NUCLEI_WEB_COUNT=$(grep -c '^[^#]' "$NUCLEI_WEB_RESULTS" 2>/dev/null || echo 0)
NUCLEI_INFRA_COUNT=$(grep -c '^[^#]' "$NUCLEI_INFRA_RESULTS" 2>/dev/null || echo 0)

# === 8️⃣ Send Telegram Notification ===
MESSAGE="🚀 Scan completed!
🔵 Alive URLs: $(wc -l < alive.txt)
🟡 Redirects: $(wc -l < redirects.txt)
🔴 Client Errors: $(wc -l < errors.txt)
🔥 Open Ports: $(wc -l < $CLEANED_PORTS)
⚡ Masscan Results: $(grep -c '^Host:' $MASSCAN_RESULTS)
🛡️ Web Vulnerabilities (Nuclei): $NUCLEI_WEB_COUNT found
📡 Infra Vulnerabilities (Nuclei): $NUCLEI_INFRA_COUNT found"

curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
     -d chat_id="$TELEGRAM_CHAT_ID" -d text="$MESSAGE"

echo "✅ Script Execution Complete!"
