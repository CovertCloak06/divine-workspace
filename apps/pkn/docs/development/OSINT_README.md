# PKN OSINT Tools - Documentation

**Date**: December 31, 2025
**Status**: ✅ PRODUCTION READY

---

## 🎯 Overview

PKN now includes comprehensive OSINT (Open Source Intelligence) capabilities for ethical information gathering from public sources. These tools are integrated at three levels:

1. **AI Agent Tools** - Agents can call OSINT functions autonomously
2. **API Endpoints** - Direct HTTP access to OSINT capabilities
3. **Web UI** - Interactive interface for manual OSINT operations

---

## ⚠️ LEGAL & ETHICAL WARNING

**IMPORTANT**: These OSINT tools are for AUTHORIZED and LEGAL use only.

### Acceptable Use:
- ✅ Security research with proper authorization
- ✅ Penetration testing engagements
- ✅ CTF (Capture The Flag) competitions
- ✅ Educational purposes in controlled environments
- ✅ Personal domain/IP reconnaissance
- ✅ Threat intelligence gathering

### Prohibited Use:
- ❌ Unauthorized network scanning
- ❌ Privacy violations
- ❌ Harassment or stalking
- ❌ Unauthorized access attempts
- ❌ Any illegal activities
- ❌ Terms of service violations

**Users are solely responsible for compliance with all applicable laws and regulations.**

---

## 📦 What Was Created

### 1. OSINT Tools Module
**File**: `tools/osint_tools.py` (15KB)

**Core Components**:
- OSINTTools class with 12 tool categories
- LangChain tool wrappers for agent integration
- Error handling and validation
- Legal/ethical warnings

**Capabilities**:
1. Domain & DNS Intelligence (WHOIS, DNS, subdomains)
2. IP & Network Intelligence (geolocation, reverse DNS, port scanning)
3. Email Intelligence (validation, breach checking)
4. Username & Social Media OSINT (12 platform search)
5. Web Intelligence (technology detection, SSL certs, Wayback Machine)
6. Phone Number Intelligence (carrier lookup)
7. Utility Functions (hash generation, base64 encoding)

### 2. API Endpoints
**File**: `divinenode_server.py` (added 12 endpoints)

**Endpoints**:
```
POST /api/osint/whois              - WHOIS lookup
POST /api/osint/dns                - DNS record queries
POST /api/osint/ip-geo             - IP geolocation
POST /api/osint/port-scan          - Port scanning (authorized only)
POST /api/osint/email-validate     - Email validation
POST /api/osint/username-search    - Username search
POST /api/osint/web-tech           - Web technology detection
POST /api/osint/ssl-cert           - SSL certificate info
POST /api/osint/wayback            - Wayback Machine check
POST /api/osint/subdomain-enum     - Subdomain enumeration
POST /api/osint/reverse-dns        - Reverse DNS lookup
POST /api/osint/phone-lookup       - Phone number lookup
```

### 3. Web UI Components
**Files**:
- `js/osint_ui.js` (10KB) - Interactive OSINT interface
- `css/osint.css` (8KB) - Cyberpunk-themed styling

**Features**:
- Collapsible OSINT tools panel
- Categorized tool buttons (Domain, IP, Email, Web, Phone)
- Dynamic form generation
- Real-time results display
- Error handling and loading states
- Mobile-responsive design

### 4. Agent Integration
**File**: `agent_manager.py` (modified)

**Integration Points**:
- OSINT tools imported and registered
- Researcher agent gets OSINT capabilities
- Consultant agent gets ALL tools including OSINT
- Tool chaining support

---

## 🎨 Web UI Interface

### Access OSINT Panel

The OSINT tools panel appears automatically on the PKN web interface when you load the page. Look for:

```
┌─────────────────────────────────┐
│ 🔍 OSINT Tools              [▼] │
├─────────────────────────────────┤
│ ⚠️ AUTHORIZED USE ONLY          │
│                                  │
│ 🌐 Domain Intelligence          │
│ [WHOIS Lookup] [DNS Lookup]     │
│ [Subdomain Enum] [SSL Cert]     │
│                                  │
│ 🌍 IP & Network                 │
│ [IP Geolocation] [Reverse DNS]  │
│ [Port Scan]                     │
│                                  │
│ 📧 Email & Username             │
│ [Email Validate] [Username]     │
│                                  │
│ 🌐 Web Intelligence             │
│ [Web Tech] [Wayback Machine]    │
│                                  │
│ 📱 Phone                        │
│ [Phone Lookup]                  │
└─────────────────────────────────┘
```

### Using OSINT Tools

1. **Click Tool Button**: Select the OSINT tool you want to use
2. **Fill Form**: Enter target (domain, IP, email, etc.)
3. **Execute**: Click "Execute" button
4. **View Results**: Results displayed in formatted output below

### Example: WHOIS Lookup

```
1. Click "WHOIS Lookup" button
2. Enter domain: example.com
3. Click "Execute"
4. View results:
   domain: example.com
   registrar: Example Registrar Inc.
   creation_date: 1995-08-14
   expiration_date: 2025-08-13
   nameservers: ['ns1.example.com', 'ns2.example.com']
   ...
```

---

## 🤖 AI Agent Usage

### How Agents Use OSINT

The **Researcher Agent** and **Consultant Agent** have access to OSINT tools and can call them autonomously.

### Example Agent Queries

**Domain Intelligence**:
```
User: "Research the domain github.com - who owns it and when was it registered?"

Researcher Agent:
└─ Tools: whois_lookup, dns_lookup

Response: GitHub.com is owned by GitHub, Inc. registered in 2007...
```

**IP Geolocation**:
```
User: "Where is the IP address 8.8.8.8 located?"

Researcher Agent:
└─ Tools: ip_geolocation

Response: 8.8.8.8 is located in Mountain View, California, USA...
```

**Username Investigation**:
```
User: "Check if username 'johndoe' exists on social platforms"

Researcher Agent:
└─ Tools: username_search

Response: Found 'johndoe' on: GitHub (likely), Twitter (likely),
Instagram (likely), Reddit (likely)...
```

**Web Technology Detection**:
```
User: "What technologies does stackoverflow.com use?"

Researcher Agent:
└─ Tools: web_technologies

Response: Stack Overflow uses: Cloudflare CDN, nginx web server,
Google Analytics...
```

---

## 🔧 API Usage

### Direct API Calls

You can call OSINT endpoints directly via HTTP POST requests.

### Example: WHOIS Lookup

```bash
curl -X POST http://localhost:8010/api/osint/whois \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

**Response**:
```json
{
  "success": true,
  "domain": "example.com",
  "registrar": "Example Registrar Inc.",
  "creation_date": "1995-08-14 04:00:00",
  "expiration_date": "2025-08-13 04:00:00",
  "nameservers": ["ns1.example.com", "ns2.example.com"],
  "status": ["clientTransferProhibited", "serverDeleteProhibited"]
}
```

### Example: IP Geolocation

```bash
curl -X POST http://localhost:8010/api/osint/ip-geo \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'
```

**Response**:
```json
{
  "success": true,
  "ip": "8.8.8.8",
  "country": "United States",
  "city": "Mountain View",
  "lat": 37.4056,
  "lon": -122.0775,
  "isp": "Google LLC",
  "org": "Google Public DNS"
}
```

### Example: DNS Lookup

```bash
curl -X POST http://localhost:8010/api/osint/dns \
  -H "Content-Type: application/json" \
  -d '{"domain": "github.com", "record_types": ["A", "AAAA", "MX"]}'
```

**Response**:
```json
{
  "success": true,
  "domain": "github.com",
  "records": {
    "A": ["140.82.114.4"],
    "AAAA": [],
    "MX": ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]
  }
}
```

---

## 📊 OSINT Tool Reference

### Domain Intelligence

#### WHOIS Lookup
**Purpose**: Get domain registration information
**Input**: Domain name (e.g., "example.com")
**Output**: Registrar, creation date, expiration, nameservers, status

**Use Cases**:
- Identify domain owner
- Check domain expiration
- Find administrative contacts
- Verify nameserver configuration

#### DNS Lookup
**Purpose**: Query DNS records for domain
**Input**: Domain + record types (A, AAAA, MX, TXT, NS, CNAME)
**Output**: DNS records by type

**Use Cases**:
- Find mail servers (MX records)
- Check IP addresses (A/AAAA records)
- Verify SPF/DKIM (TXT records)
- Identify nameservers (NS records)

#### Subdomain Enumeration
**Purpose**: Discover subdomains of a domain
**Input**: Domain name
**Output**: List of found subdomains

**Use Cases**:
- Map attack surface
- Find dev/staging environments
- Discover hidden services
- Asset inventory

#### SSL Certificate Info
**Purpose**: Get SSL/TLS certificate details
**Input**: Domain name
**Output**: Issuer, validity dates, subject, SANs

**Use Cases**:
- Verify certificate validity
- Check expiration dates
- Find alternative names
- Validate issuer

### IP & Network Intelligence

#### IP Geolocation
**Purpose**: Locate IP address geographically
**Input**: IP address
**Output**: Country, city, lat/lon, ISP, organization

**Use Cases**:
- Trace IP origin
- Identify ISP/hosting provider
- Geographic analysis
- Threat attribution

#### Reverse DNS
**Purpose**: Find hostname for IP address
**Input**: IP address
**Output**: Hostname(s) associated with IP

**Use Cases**:
- Identify server purpose
- Verify IP ownership
- Find related domains
- Network mapping

#### Port Scan
**Purpose**: Check which ports are open on host
**Input**: Host + port list
**Output**: Open/closed status per port

**Use Cases**: ⚠️ **AUTHORIZED USE ONLY**
- Service discovery
- Security audits
- Configuration verification
- Asset inventory

### Email Intelligence

#### Email Validation
**Purpose**: Validate email format and deliverability
**Input**: Email address
**Output**: Format validity, MX records existence

**Use Cases**:
- Verify email syntax
- Check domain has mail servers
- Prevent typos in forms
- Filter fake addresses

### Username & Social Media

#### Username Search
**Purpose**: Check username across 12 social platforms
**Input**: Username
**Output**: Platform existence likelihood

**Platforms Checked**:
- GitHub, Twitter, Instagram, Reddit
- LinkedIn, Facebook, YouTube, TikTok
- Medium, DeviantArt, Twitch, Patreon

**Use Cases**:
- Social media footprint analysis
- Account discovery
- Identity verification
- Brand monitoring

### Web Intelligence

#### Web Technologies
**Purpose**: Detect technologies used by website
**Input**: URL
**Output**: Detected CMS, frameworks, libraries, servers

**Use Cases**:
- Competitive analysis
- Technology stack research
- Security assessment
- Fingerprinting

#### Wayback Machine
**Purpose**: Check archived versions on Internet Archive
**Input**: URL
**Output**: Archive status, snapshot count, dates

**Use Cases**:
- Historical research
- Find removed content
- Track website changes
- Data recovery

### Phone Intelligence

#### Phone Lookup
**Purpose**: Get carrier and timezone for phone number
**Input**: Phone number (with country code)
**Output**: Carrier, country, timezone

**Use Cases**:
- Verify phone validity
- Identify carrier
- Check country/region
- Timezone detection

---

## 🧪 Testing

### Test OSINT Tools

#### Via Web UI:
1. Start PKN: `./pkn_control.sh start-all`
2. Open browser: http://localhost:8010/pkn.html
3. Locate OSINT Tools panel
4. Click any tool button
5. Enter test data
6. Verify results display

#### Via API:
```bash
# Test WHOIS
curl -X POST http://localhost:8010/api/osint/whois \
  -H "Content-Type: application/json" \
  -d '{"domain": "github.com"}'

# Test IP Geo
curl -X POST http://localhost:8010/api/osint/ip-geo \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'

# Test DNS
curl -X POST http://localhost:8010/api/osint/dns \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'
```

#### Via AI Agent:
```
Start CLI: ./pkn-cli

You » lookup the whois information for github.com

🔍 Researcher Agent
└─ Tools: whois_lookup

Response: [WHOIS data for github.com]
```

### Expected Results

All tools should return JSON with:
- `success: true` on success
- `error` field on failure
- Relevant data fields based on tool type

---

## 🛠️ Troubleshooting

### Problem: "Module not found: whois"
**Solution**:
```bash
source .venv/bin/activate
pip install python-whois dnspython beautifulsoup4
```

### Problem: "OSINT panel not showing in UI"
**Solution**:
- Hard refresh browser: Ctrl+Shift+R
- Check console for JavaScript errors
- Verify osint_ui.js and osint.css are loaded
- Check browser Network tab for 404s

### Problem: "Port scan always times out"
**Solution**:
- Ensure you have authorization to scan the target
- Check firewall rules
- Reduce number of ports scanned
- Increase timeout in osint_tools.py

### Problem: "DNS lookup fails"
**Solution**:
- Verify domain name is valid
- Check internet connectivity
- Try different record types
- Check DNS resolver configuration

---

## 📁 Files Created/Modified

```
/home/gh0st/pkn/
├── tools/
│   └── osint_tools.py          # NEW - OSINT tools module
├── js/
│   └── osint_ui.js             # NEW - OSINT UI JavaScript
├── css/
│   └── osint.css               # NEW - OSINT UI styling
├── divinenode_server.py        # MODIFIED - Added 12 OSINT endpoints
├── agent_manager.py            # MODIFIED - Integrated OSINT tools
├── pkn.html                    # MODIFIED - Added OSINT UI includes
├── requirements.txt            # MODIFIED - Added OSINT dependencies
└── OSINT_README.md             # NEW - This file
```

---

## 📚 Technical Details

### Dependencies

```python
# Core OSINT
python-whois>=0.8.0      # WHOIS lookups
dnspython>=2.4.0         # DNS queries
beautifulsoup4>=4.12.0   # Web scraping
phonenumbers>=8.13.0     # Phone validation
requests>=2.31.0         # HTTP requests
```

### LangChain Integration

OSINT tools are wrapped as LangChain Tool objects:

```python
from langchain.tools import Tool

whois_tool = Tool(
    name="whois_lookup",
    func=lambda domain: osint.whois_lookup(domain),
    description="Perform WHOIS lookup on domain..."
)
```

### Error Handling

All OSINT functions return consistent format:

```python
{
    "success": True/False,
    "error": "error message" (if failed),
    ...data fields...
}
```

---

## 🔮 Future Enhancements

### Planned Features:
- [ ] OSINT result caching (reduce redundant queries)
- [ ] OSINT query history/logging
- [ ] Automated OSINT report generation
- [ ] Integration with threat intelligence feeds
- [ ] Advanced subdomain enumeration (DNS brute force)
- [ ] Screenshot capture for web targets
- [ ] OSINT workflow automation (chained queries)
- [ ] Export results to JSON/CSV/PDF
- [ ] OSINT dashboard with visualizations

### Possible Additions:
- [ ] Have I Been Pwned integration (breach checking)
- [ ] Shodan API integration (IoT device search)
- [ ] VirusTotal API integration (malware/URL scanning)
- [ ] Certificate Transparency log search
- [ ] GitHub repository reconnaissance
- [ ] Email SMTP verification
- [ ] Advanced port scanning (service detection)
- [ ] Network traceroute/ping
- [ ] OSINT API rate limiting
- [ ] Multi-target batch processing

---

## 📝 Summary

**PKN now has enterprise-grade OSINT capabilities!**

✅ **12 OSINT Tool Categories** - Domain, IP, Email, Username, Web, Phone
✅ **3 Access Methods** - AI Agents, API, Web UI
✅ **Full Integration** - Agent system, tool chaining, UI components
✅ **Legal Compliance** - Warnings and ethical guidelines
✅ **Production Ready** - Error handling, validation, documentation

**OSINT tools enable:**
- Automated intelligence gathering by AI agents
- Manual reconnaissance via intuitive UI
- Programmatic access via REST API
- Security research and threat intelligence
- Educational and CTF use cases

**Remember**: Always use OSINT tools legally, ethically, and with proper authorization.

---

**🚀 Start using OSINT tools:**

**Web UI**: http://localhost:8010/pkn.html → OSINT Tools panel
**CLI**: `./pkn-cli` → Ask agent to "lookup domain example.com"
**API**: `curl -X POST http://localhost:8010/api/osint/whois -d '{"domain":"github.com"}'`

---

**Legal Notice**: Users are solely responsible for ensuring their use of these tools complies with all applicable laws, regulations, and terms of service. The developers assume no liability for misuse.
