# Subfinder-X-plus
🔍 **SubFinder X+** - Advanced Subdomain Discovery Suite  

**SubFinder X+** is a powerful tool to discover subdomains, combining **14 sources** (VirusTotal, URLScan, GitHub, etc.) with optimized brute-force scanning.  

---

## ✨ Features  
- ✅ **Multi-source scanning** (CERT, OTX, Anubis, etc.)  
- 🚀 **Customizable brute-force** with wordlist support  
- 📊 **Reports in HTML, JSON, and TXT formats**  
- ⚡ **Multithreading** for maximum speed  

---

## 🛠 Installation  

### Linux
```bash
# Clone the repository
git clone https://github.com/X-bro1/Subfinder-X-plus.git
cd Subfinder-X-plus

# Activate your virtual environment (if needed)
source routersploit_env
bin/activate

# Install dependencies
pip install -r requirements.txt

### Windows
```bash
 # Download and extract the repository
cd C:\Users\XXX\Desktop\Subfinder-X-plus

# Install dependencies
pip install -r requirements.txt

### Usage Examples
python subfinder.py -d Target.com --resolve -w wordlist.txt --save-all 


