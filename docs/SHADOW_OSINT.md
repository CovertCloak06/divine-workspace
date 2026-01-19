# Shadow OSINT Toolkit

Comprehensive open-source intelligence (OSINT) framework integrated into PKN (Divine Node) for reconnaissance, profiling, and intelligence gathering.

## Overview

Shadow OSINT is a powerful toolkit that provides 35 specialized tools across 8 categories for ethical reconnaissance and information gathering. Available on both desktop PKN and PKN Mobile.

**Key Features:**
- Person profiling with confidence ratings
- Domain and network reconnaissance
- Image metadata extraction and analysis
- Automated dork generation for Google, GitHub, and Shodan
- Username hunting across 100+ platforms
- Incremental profile building over time

**Availability:**
- Desktop PKN: `/home/gh0st/dvn/divine-workspace/apps/pkn/backend/tools/shadow/`
- Mobile PKN: `/home/gh0st/dvn/divine-workspace/apps/pkn-mobile/backend/tools/shadow/`

## Installation & Dependencies

### Core Dependencies (Required)
All core OSINT features work out-of-the-box with standard Python libraries.

### Optional Image Analysis Dependencies

For advanced image reconnaissance features, install:

```bash
# Image processing (EXIF, GPS extraction)
pip install Pillow

# OCR text extraction from images
pip install pytesseract
sudo apt-get install tesseract-ocr  # Linux
brew install tesseract  # macOS

# Perceptual hashing for image comparison
pip install imagehash
```

**What works without optional dependencies:**
- All person recon tools
- All domain/network recon tools
- All dork generation tools
- All profiler tools
- Basic image hash calculation (MD5, SHA256)

**What requires optional dependencies:**
- `shadow_image_exif` - Requires Pillow
- `shadow_image_gps` - Requires Pillow
- `shadow_image_ocr` - Requires pytesseract + tesseract-ocr
- `shadow_image_compare` - Requires imagehash
- `shadow_image_strip_metadata` - Requires Pillow

## Tool Categories

### 1. PERSON RECON (3 tools)

Hunt for individuals using usernames, emails, or phone numbers.

#### `shadow_username_hunt`
Hunt username across 100+ platforms including social media, developer sites, gaming, and forums.

**Usage:**
```python
# Quick scan (20 top platforms)
result = shadow_username_hunt(username="johndoe", quick=True)

# Full scan (100+ platforms)
result = shadow_username_hunt(username="johndoe", quick=False)
```

**Returns:** JSON with found profiles categorized by platform type.

#### `shadow_email_recon`
Investigate email address validity, MX records, breach databases, and Gravatar presence.

**Usage:**
```python
result = shadow_email_recon(email="john@example.com")
```

**Returns:** Format validation, MX records, disposable email detection, breach check, Gravatar status.

#### `shadow_phone_lookup`
Lookup phone number carrier, country, timezone, and type (mobile/landline/VOIP).

**Usage:**
```python
result = shadow_phone_lookup(phone="+12025551234")
```

**Returns:** Country code, carrier, timezone, number type.

---

### 2. PEOPLE SEARCH (4 tools)

Find people by real name and generate investigation leads.

#### `shadow_find_person`
Comprehensive person search by name, age, and location. Generates dorks and direct links.

**Usage:**
```python
result = shadow_find_person(
    name="John Smith",
    age=35,
    city="Seattle",
    state="WA"
)
```

**Returns:** Possible usernames, emails, Google dorks, social media links, people-finder links.

#### `shadow_generate_usernames`
Generate possible username variations from a real name.

**Usage:**
```python
result = shadow_generate_usernames(
    name="John Smith",
    birth_year=1990
)
```

**Returns:** List of username variations (johnsmith, jsmith, john.smith, johnsmith90, etc.)

#### `shadow_generate_emails`
Generate possible email variations from a real name.

**Usage:**
```python
result = shadow_generate_emails(
    name="John Smith",
    birth_year=1990
)
```

**Returns:** Email variations across gmail, yahoo, outlook, etc.

#### `shadow_people_search_links`
Get direct links to people search engines.

**Usage:**
```python
result = shadow_people_search_links(
    name="John Smith",
    city="Seattle",
    state="WA"
)
```

**Returns:** URLs for TruePeopleSearch, FastPeopleSearch, Whitepages, Spokeo, FamilyTreeNow.

---

### 3. PROFILER (6 tools)

Build intelligence profiles with confidence ratings that improve over time.

#### `shadow_create_profile`
Create a person profile with confidence scores.

**Usage:**
```python
result = shadow_create_profile(
    name="John Smith",
    age=35,
    city="Seattle",
    state="WA",
    email="john@example.com",
    phone="+12025551234"
)
```

**Returns:** Profile ID, generated usernames/emails, confidence scores, summary.

#### `shadow_enrich_profile`
Enrich existing profile with username hunts or email checks.

**Usage:**
```python
result = shadow_enrich_profile(
    profile_id="abc123def456",
    username_to_hunt="jsmith",
    email_to_check="john@example.com"
)
```

**Returns:** Updated profile with found accounts and adjusted confidence scores.

#### `shadow_profile_summary`
Get quick summary of profile findings.

**Usage:**
```python
result = shadow_profile_summary(profile_id="abc123def456")
```

**Returns:** Confidence percentage, verified accounts count, possible usernames count.

#### `shadow_list_profiles`
List all active and saved profiles.

**Usage:**
```python
result = shadow_list_profiles()
```

**Returns:** Active profiles (in memory) and saved profiles (on disk).

#### `shadow_save_profile`
Save profile to disk for later use.

**Usage:**
```python
result = shadow_save_profile(profile_id="abc123def456")
```

**Returns:** Filepath where profile was saved (`~/.shadow_profiles/`).

#### `shadow_quick_profile`
Create profile AND hunt top usernames immediately.

**Usage:**
```python
result = shadow_quick_profile(
    name="John Smith",
    age=35,
    city="Seattle",
    state="WA"
)
```

**Returns:** Complete profile with hunted accounts for top 3 most likely usernames.

---

### 4. DOMAIN RECON (4 tools)

Investigate domains, subdomains, and web technologies.

#### `shadow_domain_recon`
Full domain reconnaissance: DNS, SSL, subdomains, technologies.

**Usage:**
```python
result = shadow_domain_recon(domain="example.com")
```

**Returns:** DNS records, SSL certificate info, subdomains, detected technologies.

#### `shadow_subdomain_enum`
Enumerate subdomains via Certificate Transparency logs and wordlists.

**Usage:**
```python
result = shadow_subdomain_enum(domain="example.com")
```

**Returns:** List of discovered subdomains.

#### `shadow_tech_detect`
Detect website technologies (CMS, CDN, frameworks, analytics).

**Usage:**
```python
result = shadow_tech_detect(domain="example.com")
```

**Returns:** WordPress, Cloudflare, React, Google Analytics, etc.

#### `shadow_whois`
WHOIS lookup for domain registration information.

**Usage:**
```python
result = shadow_whois(domain="example.com")
```

**Returns:** Registrar, creation/expiration dates, nameservers, registrant contact.

---

### 5. NETWORK RECON (4 tools)

IP address investigation and geolocation.

#### `shadow_ip_recon`
Full IP reconnaissance: geolocation, Shodan, reverse DNS.

**Usage:**
```python
result = shadow_ip_recon(ip="8.8.8.8")
```

**Returns:** Geo data, Shodan findings, reverse DNS, reputation.

#### `shadow_geolocate`
IP geolocation lookup.

**Usage:**
```python
result = shadow_geolocate(ip="8.8.8.8")
```

**Returns:** Country, city, ISP, organization, coordinates.

#### `shadow_shodan_lookup`
Query Shodan InternetDB (free, no API key required).

**Usage:**
```python
result = shadow_shodan_lookup(ip="8.8.8.8")
```

**Returns:** Open ports, hostnames, CPEs, known vulnerabilities, tags.

#### `shadow_reverse_dns`
Reverse DNS lookup - find hostnames for an IP.

**Usage:**
```python
result = shadow_reverse_dns(ip="8.8.8.8")
```

**Returns:** Hostnames pointing to this IP.

---

### 6. DORK GENERATION (3 tools)

Generate search queries for Google, GitHub, and Shodan.

#### `shadow_google_dorks`
Generate Google dorks for finding exposed files, admin panels, credentials.

**Usage:**
```python
# Domain target
result = shadow_google_dorks(target="example.com", target_type="domain")

# Company name
result = shadow_google_dorks(target="Acme Corp", target_type="company")

# Username
result = shadow_google_dorks(target="johndoe", target_type="username")
```

**Returns:** Categorized dorks with direct Google search URLs.

#### `shadow_github_dorks`
Generate GitHub search dorks for exposed credentials and secrets.

**Usage:**
```python
result = shadow_github_dorks(target="acmecorp", target_type="org")
```

**Returns:** GitHub queries with URLs for finding API keys, passwords, config files.

#### `shadow_shodan_dorks`
Generate Shodan search queries for vulnerable services.

**Usage:**
```python
result = shadow_shodan_dorks(target="example.com")
```

**Returns:** Shodan queries for exposed databases, IoT devices, admin panels.

---

### 7. ORCHESTRATION (3 tools)

High-level automated reconnaissance workflows.

#### `shadow_quick_recon`
Auto-detect target type and run appropriate recon.

**Usage:**
```python
# Detects type automatically
result = shadow_quick_recon(target="8.8.8.8")  # IP
result = shadow_quick_recon(target="example.com")  # Domain
result = shadow_quick_recon(target="john@example.com")  # Email
result = shadow_quick_recon(target="+12025551234")  # Phone
result = shadow_quick_recon(target="johndoe")  # Username
```

**Returns:** Detected type + appropriate reconnaissance results.

#### `shadow_investigate_person`
Full person investigation from multiple identifiers.

**Usage:**
```python
result = shadow_investigate_person(
    username="johndoe",
    email="john@example.com",
    phone="+12025551234"
)
```

**Returns:** Comprehensive profile combining all available data points.

#### `shadow_generate_all_dorks`
Generate dorks for all platforms (Google, GitHub, Shodan).

**Usage:**
```python
result = shadow_generate_all_dorks(target="example.com")
```

**Returns:** Complete dork collection across all platforms.

---

### 8. IMAGE RECON (8 tools)

Extract intelligence from images and photos.

#### `shadow_image_analyze`
Full image analysis: EXIF, GPS, hashes, reverse search URLs.

**Usage:**
```python
result = shadow_image_analyze(image_path="/path/to/photo.jpg")
```

**Returns:** Complete analysis with all available metadata.

#### `shadow_image_exif`
Extract EXIF metadata (camera, software, dates).

**Usage:**
```python
result = shadow_image_exif(image_path="/path/to/photo.jpg")
```

**Returns:** Camera make/model, software, dates, serial numbers.

**Intel value:** Can identify what device took the photo and when.

#### `shadow_image_gps`
Extract GPS coordinates from image metadata.

**Usage:**
```python
result = shadow_image_gps(image_path="/path/to/photo.jpg")
```

**Returns:** Latitude, longitude, Google Maps link.

**Intel value:** Many phone photos contain exact location data.

#### `shadow_image_ocr`
Extract text from image using OCR.

**Usage:**
```python
result = shadow_image_ocr(image_path="/path/to/screenshot.png")
```

**Returns:** Extracted text + identified patterns (emails, phones, URLs, social handles).

#### `shadow_image_reverse_search`
Get reverse image search URLs.

**Usage:**
```python
result = shadow_image_reverse_search(image_path="/path/to/photo.jpg")
```

**Returns:** URLs for Google, TinEye, Yandex, Bing, Baidu.

**Note:** Returns URLs only - you must upload the image manually to search engines.

#### `shadow_image_compare`
Compare two images for similarity using perceptual hashing.

**Usage:**
```python
result = shadow_image_compare(
    image1_path="/path/to/photo1.jpg",
    image2_path="/path/to/photo2.jpg"
)
```

**Returns:** Similarity score + interpretation (identical, similar, different).

**Intel value:** Detects if images are the same even if resized, cropped, or filtered.

#### `shadow_image_hash`
Calculate file and perceptual hashes.

**Usage:**
```python
result = shadow_image_hash(image_path="/path/to/photo.jpg")
```

**Returns:** MD5, SHA256, pHash, aHash, dHash.

**Intel value:** Track images across platforms and find duplicates.

#### `shadow_image_strip_metadata`
Remove all metadata from image for privacy.

**Usage:**
```python
result = shadow_image_strip_metadata(
    image_path="/path/to/original.jpg",
    output_path="/path/to/cleaned.jpg"  # Optional
)
```

**Returns:** Path to cleaned image with all EXIF/GPS removed.

---

## Profiler Workflow

The profiler system allows building intelligence profiles incrementally over time with confidence ratings.

### Basic Workflow

```python
# 1. Create initial profile
profile_json = shadow_create_profile(
    name="John Smith",
    age=35,
    city="Seattle",
    state="WA"
)

# Parse profile_id from response
import json
profile_data = json.loads(profile_json)
profile_id = profile_data["profile_id"]

# 2. Enrich with username hunt
shadow_enrich_profile(
    profile_id=profile_id,
    username_to_hunt="jsmith"
)

# 3. Enrich with email check
shadow_enrich_profile(
    profile_id=profile_id,
    email_to_check="john.smith@gmail.com"
)

# 4. Get summary
summary = shadow_profile_summary(profile_id=profile_id)

# 5. Save for later
shadow_save_profile(profile_id=profile_id)
```

### Advanced Workflow: Quick Profile

For fast results when you have a name:

```python
# Creates profile + hunts top 3 most likely usernames automatically
result = shadow_quick_profile(
    name="John Smith",
    age=35,
    city="Seattle",
    state="WA"
)
```

### Confidence Ratings

Profiles assign confidence scores (0.0 to 1.0) to all data:

- **User input:** 0.9 confidence (high trust)
- **Generated usernames:** 0.3 confidence (educated guess)
- **Found accounts:** 0.85 confidence (verified existence)
- **Verified email:** 1.0 confidence (MX records valid)

**Overall confidence** combines weighted scores from all fields.

### Profile Storage

- **Active profiles:** Stored in memory during session
- **Saved profiles:** Written to `~/.shadow_profiles/` directory
- **Format:** JSON files named `{profile_id}.json`

---

## Image Analysis Workflow

Extract maximum intelligence from images:

### Full Analysis

```python
# Get everything in one call
result = shadow_image_analyze(image_path="/path/to/photo.jpg")

# Returns:
# - EXIF metadata (camera, software, dates)
# - GPS coordinates if available
# - File hashes (MD5, SHA256)
# - Perceptual hashes (pHash, aHash, dHash)
# - Reverse image search URLs
```

### Targeted Extraction

```python
# Just GPS coordinates
gps = shadow_image_gps(image_path="/path/to/photo.jpg")

# Just text extraction
text = shadow_image_ocr(image_path="/path/to/screenshot.png")

# Just camera info
exif = shadow_image_exif(image_path="/path/to/photo.jpg")
```

### Privacy Workflow

```python
# Before sharing an image online, strip metadata:
result = shadow_image_strip_metadata(
    image_path="/path/to/original.jpg",
    output_path="/path/to/safe.jpg"
)

# Upload the cleaned version to protect your privacy
```

### Image Tracking

```python
# Calculate hashes to track image across platforms
hashes = shadow_image_hash(image_path="/path/to/photo.jpg")

# Compare suspected copies
similarity = shadow_image_compare(
    image1_path="/path/to/original.jpg",
    image2_path="/path/to/suspected_copy.jpg"
)
```

---

## Usage in PKN

### Chat Interface

All Shadow tools are available via natural language in PKN chat:

```
You: Hunt for username "johndoe" across social media

PKN: [Uses shadow_username_hunt internally]
     Found johndoe on:
     - GitHub: https://github.com/johndoe
     - Twitter: https://twitter.com/johndoe
     - Reddit: https://reddit.com/u/johndoe
     ...
```

### API Access

Desktop PKN exposes Shadow tools via API endpoints:

```bash
# OSINT endpoint
curl -X POST http://localhost:8010/api/osint/username-hunt \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe", "quick": true}'

# Domain recon
curl -X POST http://localhost:8010/api/osint/domain-recon \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Python Agent Usage

Agents can call Shadow tools directly:

```python
from tools.shadow import shadow_username_hunt, shadow_create_profile

# In agent code
result = shadow_username_hunt(username="johndoe", quick=True)

profile = shadow_create_profile(
    name="John Smith",
    age=35,
    city="Seattle",
    state="WA"
)
```

---

## Legal & Ethical Notice

**IMPORTANT: Shadow OSINT is designed for legitimate security research, OSINT investigations, and educational purposes only.**

### Permitted Uses
- Security research and penetration testing (with authorization)
- OSINT investigations within legal boundaries
- Educational learning and skill development
- Personal privacy audits (your own data)
- Competitive intelligence (public information only)

### Prohibited Uses
- Unauthorized access to systems or accounts
- Harassment, stalking, or doxing
- Identity theft or fraud
- Violation of privacy laws (GDPR, CCPA, etc.)
- Any illegal activity

### Best Practices
1. **Get permission** before investigating individuals or organizations
2. **Respect privacy** - just because data is public doesn't mean it should be exploited
3. **Follow laws** - OSINT laws vary by jurisdiction
4. **Document consent** for all investigations
5. **Secure findings** - protect sensitive data you discover
6. **Report responsibly** - disclose vulnerabilities through proper channels

### Disclaimer
The developers of Shadow OSINT are not responsible for misuse of these tools. Users assume all legal liability for their actions.

---

## Platform Availability

### Desktop PKN
Full Shadow toolkit available at:
- **Location:** `/home/gh0st/dvn/divine-workspace/apps/pkn/backend/tools/shadow/`
- **Access:** Chat interface, API endpoints, agent tools
- **Image tools:** Fully supported (install optional dependencies)

### Mobile PKN
Full Shadow toolkit available at:
- **Location:** `/home/gh0st/dvn/divine-workspace/apps/pkn-mobile/backend/tools/shadow/`
- **Access:** Chat interface, API endpoints, agent tools
- **Image tools:** OCR may have performance limitations on mobile

### Shared Codebase
Both desktop and mobile use the same Shadow implementation - changes in one automatically apply to both.

---

## Module Structure

Shadow OSINT is organized into focused Python modules:

```
tools/shadow/
├── __init__.py           # Package initialization
├── tools.py              # LangChain tool wrappers (35 tools)
├── engine.py             # Orchestration engine
├── person.py             # Username, email, phone recon
├── people.py             # Name-based person search
├── profiler.py           # Profile building with confidence
├── domain.py             # Domain reconnaissance
├── network.py            # IP and network recon
├── dorks.py              # Dork generation
└── images.py             # Image metadata extraction
```

**Total:** 35 tools across 8 categories

---

## Future Enhancements

Planned features (not yet implemented):

- Social graph mapping (connect related profiles)
- Timeline reconstruction from multiple sources
- Automated report generation
- Dark web monitoring integration
- Cryptocurrency address tracking
- Facial recognition via external APIs
- Additional breach databases
- Tor/I2P hidden service enumeration

---

## Contributing

Shadow OSINT is part of the Divine Workspace monorepo.

**To contribute:**
1. Follow project architecture standards in `/home/gh0st/dvn/ARCHITECTURE_STANDARDS.md`
2. Keep tool modules under 200 lines
3. Add comprehensive docstrings to all tools
4. Test on both desktop and mobile PKN
5. Run `just ci` before committing

---

## Support

For issues, questions, or feature requests:
- GitHub: https://github.com/CovertCloak06/divine-workspace
- Check existing documentation in `docs/` directory
- Review CLAUDE.md files in each app directory

---

**Version:** 1.0
**Last Updated:** 2026-01-18
**Maintained by:** Divine Workspace Team
