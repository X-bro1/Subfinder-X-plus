# Subfinder-X-plus
🔍 SubFinder X+ - Advanced Subdomain Discovery Suite  

SubFinder X+ is a powerful tool to discover subdomains, combining 14 sources (VirusTotal, URLScan, GitHub, etc.) with optimized brute-force scanning.  

---

###✨ Features  
- ✅ Multi-source scanning** (CERT, OTX, Anubis, etc.)  
- 🚀 Customizable brute-force** with wordlist support  
- 📊 Reports in HTML, JSON, and TXT formats**  
- ⚡ Multithreading** for maximum speed

# Main Options
- -d / --domain : target domain to scan
- --resolve : resolve subdomains to IP addresses
- -w / --wordlist : custom wordlist for brute-force
- --save-all : save all results (JSON, TXT, HTML)
- --threads : number of threads to use for faster scanning

### 💡 Tips

- Make sure you have Python ≥ 3.9 installed
- Use a wordlist suited to your target for better results
- Increase threads for faster execution if your system allows

## Disclaimer
- Use this tool only on domains you own or have explicit permission to test. Unauthorized scanning may be illegal and is your responsibility.

## 🔗 Support / Donate

- If you find this tool helpful, consider supporting me on Ko-fi : https://ko-fi.com/xbro1 ☕️

---

### 🛠 Installation  

## Windows
```bash
 # Download and extract the repository
cd Subfinder-X-plus
pip install -r requirements.txt
```

## Linux
```bash

git clone https://github.com/X-bro1/Subfinder-X-plus.git
# Activate your virtual environment
source routersploit_env
bin/activate
pip install -r requirements.txt
cd Subfinder-X-plus
```

### Usage Examples Linux / Windows
```bash
python subfinder.py -d Target.com --resolve -w wordlist.txt --save-all 
```

