# Subfinder-X-plus
🔍 SubFinder X+ - Advanced Subdomain Discovery Suite  

SubFinder X+ is a powerful tool to discover subdomains, combining 14 sources (VirusTotal, URLScan, GitHub, etc.) with optimized brute-force scanning.  

### ✨ Features
- ✅ Multi-source scanning (CERT, OTX, Anubis, HackerTarget, SecurityTrails, Censys, Shodan, VirusTotal, URLScan, GitHub, Google, Bing, ThreatCrowd, BufferOver)
- 🚀 Customizable brute-force with wordlist support and adjustable threads
- 📊 Comprehensive reports in HTML, JSON, and TXT formats
- ⚡ Multithreading (up to 200 threads) for maximum speed
- 🌐 DNS resolution and port scanning (80, 443, 21, 22, 25, 8080, 8443)
- 💾 Auto-save functionality with dedicated results folder
- 🎨 Rich console interface with progress bars and colored output
- 🔄 Graceful CTRL+C handling with automatic backup
- 🔍 Reverse DNS lookup for additional subdomain discovery
- 🤝 Support integration with multiple APIs (SecurityTrails, Censys, Shodan, VirusTotal)
- 🌐 Massive subdomain resolution with bulk DNS lookup
- 📡 Unique IP detection and deduplication
- 🔌 IPv4 support for all network operations

> ### ⚠️ Note: 
>  DNS resolution and port scanning may take a significant amount of time, depending on the quality of the discovered subdomains.  
>  The same applies to brute-forcing and resolving DNS for identified subdomains.  
💡 If you stop the scan, all results discovered up to that point will be saved.

### 🛠 Installation  

## Windows
```bash
 # Download and extract the repository
cd Subfinder-X-plus
pip install -r requirements.txt
# Add your free or premium API keys in the .env file
 Modify the .env file and add your API keys (free and premium)
```

## Linux
```bash

git clone https://github.com/X-bro1/Subfinder-X-plus.git
# Activate your virtual environment
source routersploit_env
bin/activate
pip install -r requirements.txt
# Add your free or premium API keys in the .env file
nano .env :  Modify the .env file and add your API keys (free and premium)
cd Subfinder-X-plus
```

### Usage Examples Linux / Windows
```bash
# Maximum performance with large wordlist
python Subfinder-X-plus.py -d example.com --resolve -w wordlist.txt --save-all
python Subfinder-X-plus.py -d example.com -w wordlist.txt -t 200 -r

# Quick scan without resolution  
python sSubfinder-X-plus.py -d example.com

# Save specific format only
python Subfinder-X-plus.py -d example.com -o output.html
```


# Main Options
```bash
- -d, --domain      # Target domain (required)
- -r, --resolve     # Enable DNS resolution + port scanning
- -w, --wordlist    #  Path to wordlist for bruteforce
- -t, --threads     # Number of threads (default: 200)
- --save-all :      # Save all report formats (JSON, TXT, HTML)
- -o, --output      # Custom output file
- -h, --help        # Show this help message and exit
```

### 💡 Tips

- Make sure you have Python ≥ 3.9 installed
- Use a wordlist suited to your target for better results
- Increase threads for faster execution if your system allows

### Disclaimer
- Use this tool only on domains you own or have explicit permission to test. Unauthorized scanning may be illegal and is your responsibility.

### 🔗 Support / Donate

- If you find this tool helpful, consider supporting me on Ko-fi : https://ko-fi.com/xbro1 ☕️

---



