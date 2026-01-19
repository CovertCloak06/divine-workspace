#!/usr/bin/env python3
"""
Shadow OSINT - LangChain Tool Wrappers
Exposes Shadow capabilities as LangChain tools for agent use
"""

import json
from langchain_core.tools import tool

from .engine import ShadowEngine
from .person import PersonRecon
from .domain import DomainRecon
from .network import NetworkRecon
from .dorks import DorkGenerator
from .people import PeopleSearch
from .profiler import Profiler, PersonProfile
from .images import ImageRecon

# Initialize modules
_engine = ShadowEngine()
_person = PersonRecon()
_domain = DomainRecon()
_network = NetworkRecon()
_dorks = DorkGenerator()
_people = PeopleSearch()
_profiler = Profiler()
_images = ImageRecon()


# ============================================
# PERSON RECONNAISSANCE TOOLS
# ============================================

@tool
def shadow_username_hunt(username: str, quick: bool = True) -> str:
    """
    Hunt for a username across 100+ platforms.

    Checks social media, developer sites, gaming, forums, and more.
    Use quick=True for fast check (20 platforms), False for full scan.

    Args:
        username: Username to search for
        quick: True for quick scan, False for comprehensive

    Returns:
        JSON with found profiles, categories, and URLs
    """
    result = _person.username_check(username, quick=quick)
    return json.dumps(result, indent=2)


@tool
def shadow_email_recon(email: str) -> str:
    """
    Investigate an email address.

    Checks: format, MX records, disposable detection, breach databases, Gravatar.

    Args:
        email: Email address to investigate

    Returns:
        JSON with email analysis results
    """
    result = _person.email_recon(email)
    return json.dumps(result, indent=2)


@tool
def shadow_phone_lookup(phone: str) -> str:
    """
    Lookup phone number information.

    Gets: country, carrier, timezone, number type (mobile/landline/voip).

    Args:
        phone: Phone number with country code (e.g., +1234567890)

    Returns:
        JSON with phone analysis results
    """
    result = _person.phone_recon(phone)
    return json.dumps(result, indent=2)


@tool
def shadow_find_person(
    name: str,
    age: int = None,
    city: str = None,
    state: str = None
) -> str:
    """
    Search for a person by name, approximate age, and location.

    Generates: possible usernames, emails, Google dorks, social media
    searches, people-finder links, and public records queries.

    Args:
        name: Full name (e.g., "John Smith")
        age: Approximate age (optional, helps narrow down)
        city: City they might live in (optional)
        state: State/province (optional)

    Returns:
        JSON with usernames, emails, dorks, and search links
    """
    result = _people.search_person(
        name=name,
        age=age,
        city=city,
        state=state
    )
    return json.dumps(result, indent=2)


@tool
def shadow_generate_usernames(name: str, birth_year: int = None) -> str:
    """
    Generate possible usernames from a real name.

    Creates variations like: johnsmith, john.smith, jsmith, johnsmith90, etc.

    Args:
        name: Full name (e.g., "John Smith")
        birth_year: Birth year for year-based variations (optional)

    Returns:
        JSON list of possible usernames
    """
    parts = name.strip().split()
    first = parts[0].lower() if parts else ""
    last = parts[-1].lower() if len(parts) > 1 else ""

    birth_years = [birth_year] if birth_year else []

    usernames = _people._generate_usernames(first, last, birth_years)
    return json.dumps({
        "name": name,
        "birth_year": birth_year,
        "usernames": usernames,
        "count": len(usernames)
    }, indent=2)


@tool
def shadow_generate_emails(name: str, birth_year: int = None) -> str:
    """
    Generate possible email addresses from a name.

    Creates variations across gmail, yahoo, outlook, etc.

    Args:
        name: Full name
        birth_year: Birth year for variations (optional)

    Returns:
        JSON list of possible emails
    """
    parts = name.strip().split()
    first = parts[0].lower() if parts else ""
    last = parts[-1].lower() if len(parts) > 1 else ""

    birth_years = [birth_year] if birth_year else []

    emails = _people._generate_emails(first, last, birth_years)
    return json.dumps({
        "name": name,
        "birth_year": birth_year,
        "emails": emails,
        "count": len(emails)
    }, indent=2)


@tool
def shadow_people_search_links(
    name: str,
    city: str = None,
    state: str = None
) -> str:
    """
    Get direct links to people search engines for a name.

    Returns links to: TruePeopleSearch, FastPeopleSearch, Whitepages,
    Spokeo, FamilyTreeNow, and more.

    Args:
        name: Full name to search
        city: City (optional, improves accuracy)
        state: State (optional)

    Returns:
        JSON with search engine links
    """
    location = _people._build_location(city, state)
    links = _people._direct_search_links(name, location)
    return json.dumps({
        "name": name,
        "location": {"city": city, "state": state},
        "search_links": links
    }, indent=2)


# ============================================
# PROFILER TOOLS (Build profiles with confidence)
# ============================================

@tool
def shadow_create_profile(
    name: str = None,
    age: int = None,
    city: str = None,
    state: str = None,
    email: str = None,
    phone: str = None
) -> str:
    """
    Create a person profile with confidence ratings.

    Automatically generates possible usernames, emails, and assigns
    probability scores. Profile can be enriched over time.

    Args:
        name: Full name (e.g., "John Smith")
        age: Approximate age
        city: City they might live in
        state: State/province
        email: Known email address
        phone: Known phone number

    Returns:
        JSON profile with confidence scores and generated leads
    """
    profile = _profiler.create_profile(
        name=name,
        age=age,
        city=city,
        state=state,
        email=email,
        phone=phone
    )
    return profile.to_json()


@tool
def shadow_enrich_profile(
    profile_id: str,
    username_to_hunt: str = None,
    email_to_check: str = None
) -> str:
    """
    Enrich an existing profile with additional searches.

    Hunts usernames across platforms, checks emails for validity
    and breach data. Updates confidence scores.

    Args:
        profile_id: ID of profile to enrich
        username_to_hunt: Username to search across platforms
        email_to_check: Email to verify and check for breaches

    Returns:
        Updated profile JSON with new findings
    """
    profile = _profiler.active_profiles.get(profile_id)
    if not profile:
        return json.dumps({"error": f"Profile {profile_id} not found"})

    if username_to_hunt:
        profile = _profiler.enrich_with_username_hunt(profile, username_to_hunt)

    if email_to_check:
        profile = _profiler.enrich_with_email_check(profile, email_to_check)

    return profile.to_json()


@tool
def shadow_profile_summary(profile_id: str) -> str:
    """
    Get a quick summary of a profile's findings.

    Shows: confidence %, verified accounts, possible usernames count.

    Args:
        profile_id: ID of profile

    Returns:
        JSON summary with key stats
    """
    profile = _profiler.active_profiles.get(profile_id)
    if not profile:
        return json.dumps({"error": f"Profile {profile_id} not found"})

    summary = _profiler.get_profile_summary(profile)
    return json.dumps(summary, indent=2)


@tool
def shadow_list_profiles() -> str:
    """
    List all saved profiles.

    Returns:
        JSON list of profiles with IDs and confidence levels
    """
    # Include active (in-memory) profiles
    active = [
        {
            "profile_id": p.profile_id,
            "name": p.get_best_name(),
            "confidence": f"{p.overall_confidence * 100:.0f}%",
            "accounts": len(p.accounts),
            "status": "active"
        }
        for p in _profiler.active_profiles.values()
    ]

    # Include saved profiles
    saved = _profiler.list_profiles()
    for s in saved:
        s["status"] = "saved"

    return json.dumps({
        "active_profiles": active,
        "saved_profiles": saved
    }, indent=2)


@tool
def shadow_save_profile(profile_id: str) -> str:
    """
    Save a profile to disk for later use.

    Args:
        profile_id: ID of profile to save

    Returns:
        Path where profile was saved
    """
    profile = _profiler.active_profiles.get(profile_id)
    if not profile:
        return json.dumps({"error": f"Profile {profile_id} not found"})

    filepath = _profiler.save_profile(profile)
    return json.dumps({
        "saved": True,
        "profile_id": profile_id,
        "filepath": filepath
    }, indent=2)


@tool
def shadow_quick_profile(
    name: str,
    age: int = None,
    city: str = None,
    state: str = None
) -> str:
    """
    Quick profile: Create profile AND hunt top usernames immediately.

    Creates profile, generates usernames, then hunts the most likely
    ones across platforms. Returns full findings in one call.

    Args:
        name: Full name
        age: Approximate age
        city: City
        state: State

    Returns:
        Complete profile with hunted accounts
    """
    # Create profile
    profile = _profiler.create_profile(
        name=name,
        age=age,
        city=city,
        state=state
    )

    # Get top 3 most likely usernames and hunt them
    top_usernames = sorted(
        profile.usernames,
        key=lambda x: x.confidence,
        reverse=True
    )[:3]

    for username_field in top_usernames:
        profile = _profiler.enrich_with_username_hunt(
            profile,
            username_field.value
        )

    return profile.to_json()


# ============================================
# IMAGE RECONNAISSANCE TOOLS
# ============================================

@tool
def shadow_image_analyze(image_path: str) -> str:
    """
    Full image analysis: EXIF, GPS, hashes, OCR.

    Extracts: camera model, GPS coordinates, timestamps, text,
    and generates reverse image search URLs.

    Args:
        image_path: Path to image file

    Returns:
        JSON with complete image analysis
    """
    result = _images.full_analysis(image_path)
    return json.dumps(result, indent=2, default=str)


@tool
def shadow_image_exif(image_path: str) -> str:
    """
    Extract EXIF metadata from image.

    Gets: camera make/model, software, dates, serial numbers.
    Can reveal what device took the photo and when.

    Args:
        image_path: Path to image file

    Returns:
        JSON with EXIF data
    """
    result = _images.extract_exif(image_path)
    return json.dumps(result, indent=2, default=str)


@tool
def shadow_image_gps(image_path: str) -> str:
    """
    Extract GPS coordinates from image.

    If found, returns lat/lon and Google Maps link.
    Many phone photos contain exact location data!

    Args:
        image_path: Path to image file

    Returns:
        JSON with GPS coordinates and map links
    """
    result = _images.extract_gps(image_path)
    return json.dumps(result, indent=2, default=str)


@tool
def shadow_image_ocr(image_path: str) -> str:
    """
    Extract text from image using OCR.

    Also identifies patterns: emails, phones, URLs, social handles.

    Args:
        image_path: Path to image file

    Returns:
        JSON with extracted text and patterns
    """
    result = _images.extract_text(image_path)
    return json.dumps(result, indent=2, default=str)


@tool
def shadow_image_reverse_search(image_path: str) -> str:
    """
    Get reverse image search URLs.

    Returns URLs for: Google, TinEye, Yandex, Bing, Baidu.
    Upload the image to find where it appears online.

    Args:
        image_path: Path to image file

    Returns:
        JSON with search engine URLs and instructions
    """
    result = _images.get_reverse_search_urls(image_path)
    return json.dumps(result, indent=2)


@tool
def shadow_image_compare(image1_path: str, image2_path: str) -> str:
    """
    Compare two images for similarity.

    Uses perceptual hashing to detect if images are related
    even if resized, cropped, or filtered.

    Args:
        image1_path: Path to first image
        image2_path: Path to second image

    Returns:
        JSON with similarity score and interpretation
    """
    result = _images.compare_images(image1_path, image2_path)
    return json.dumps(result, indent=2)


@tool
def shadow_image_hash(image_path: str) -> str:
    """
    Calculate image hashes for identification.

    Returns: MD5, SHA256, and perceptual hashes (pHash, aHash, dHash).
    Use for finding duplicates or tracking image across platforms.

    Args:
        image_path: Path to image file

    Returns:
        JSON with various hash values
    """
    result = _images.calculate_hashes(image_path)
    return json.dumps(result, indent=2)


@tool
def shadow_image_strip_metadata(image_path: str, output_path: str = None) -> str:
    """
    Remove all metadata from image for privacy.

    Creates a clean copy with EXIF, GPS, camera info stripped.

    Args:
        image_path: Path to original image
        output_path: Path for cleaned image (optional)

    Returns:
        JSON with path to cleaned image
    """
    result = _images.strip_metadata(image_path, output_path)
    return json.dumps(result, indent=2)


# ============================================
# DOMAIN RECONNAISSANCE TOOLS
# ============================================

@tool
def shadow_domain_recon(domain: str) -> str:
    """
    Full domain reconnaissance.

    Gathers: DNS records, SSL info, subdomains, technologies, certificates.

    Args:
        domain: Domain to investigate (e.g., example.com)

    Returns:
        JSON with comprehensive domain intelligence
    """
    result = _domain.full_recon(domain)
    return json.dumps(result, indent=2, default=str)


@tool
def shadow_subdomain_enum(domain: str) -> str:
    """
    Enumerate subdomains for a domain.

    Uses: Certificate Transparency logs, HackerTarget API, common wordlist.

    Args:
        domain: Target domain

    Returns:
        JSON with discovered subdomains
    """
    result = _domain.subdomain_enum(domain)
    return json.dumps(result, indent=2)


@tool
def shadow_tech_detect(domain: str) -> str:
    """
    Detect technologies used by a website.

    Identifies: CMS, frameworks, CDN, analytics, security headers.

    Args:
        domain: Target domain

    Returns:
        JSON with detected technologies
    """
    result = _domain.tech_detect(domain)
    return json.dumps(result, indent=2)


@tool
def shadow_whois(domain: str) -> str:
    """
    WHOIS lookup for domain registration info.

    Gets: registrar, dates, nameservers, status, contact emails.

    Args:
        domain: Domain to lookup

    Returns:
        JSON with WHOIS data
    """
    result = _domain.whois_lookup(domain)
    return json.dumps(result, indent=2, default=str)


# ============================================
# NETWORK RECONNAISSANCE TOOLS
# ============================================

@tool
def shadow_ip_recon(ip: str) -> str:
    """
    Full IP address reconnaissance.

    Gathers: geolocation, Shodan data, reverse DNS, reputation.

    Args:
        ip: IP address to investigate

    Returns:
        JSON with comprehensive IP intelligence
    """
    result = _network.full_recon(ip)
    return json.dumps(result, indent=2)


@tool
def shadow_geolocate(ip: str) -> str:
    """
    Geolocate an IP address.

    Gets: country, city, ISP, organization, coordinates.

    Args:
        ip: IP address to geolocate

    Returns:
        JSON with geolocation data
    """
    result = _network.geolocate(ip)
    return json.dumps(result, indent=2)


@tool
def shadow_shodan_lookup(ip: str) -> str:
    """
    Query Shodan InternetDB for IP information.

    Gets: open ports, hostnames, CPEs, known vulnerabilities, tags.
    No API key required (uses free InternetDB).

    Args:
        ip: IP address to lookup

    Returns:
        JSON with Shodan data
    """
    result = _network.shodan_lookup(ip)
    return json.dumps(result, indent=2)


@tool
def shadow_reverse_dns(ip: str) -> str:
    """
    Reverse DNS lookup - find hostnames for an IP.

    Args:
        ip: IP address

    Returns:
        JSON with hostnames pointing to this IP
    """
    result = _network.reverse_dns(ip)
    return json.dumps(result, indent=2)


# ============================================
# DORK GENERATION TOOLS
# ============================================

@tool
def shadow_google_dorks(target: str, target_type: str = "domain") -> str:
    """
    Generate Google dorks for a target.

    Creates search queries to find: exposed files, admin panels,
    credentials, error messages, and more.

    Args:
        target: Domain, company name, username, or email
        target_type: One of "domain", "company", "username", "email"

    Returns:
        JSON with categorized dorks and search URLs
    """
    result = _dorks.google_dorks(target, target_type)
    return json.dumps(result, indent=2)


@tool
def shadow_github_dorks(target: str, target_type: str = "org") -> str:
    """
    Generate GitHub search dorks.

    Finds: exposed credentials, config files, private keys, database dumps.

    Args:
        target: Organization name, username, or domain
        target_type: One of "org", "user", "domain"

    Returns:
        JSON with GitHub search queries and URLs
    """
    result = _dorks.github_dorks(target, target_type)
    return json.dumps(result, indent=2)


@tool
def shadow_shodan_dorks(target: str = None) -> str:
    """
    Generate Shodan search queries.

    Creates queries for: vulnerable services, exposed databases,
    IoT devices, admin panels.

    Args:
        target: Optional domain/org to focus search

    Returns:
        JSON with Shodan queries and URLs
    """
    result = _dorks.shodan_dorks(target)
    return json.dumps(result, indent=2)


# ============================================
# ORCHESTRATION TOOLS
# ============================================

@tool
def shadow_quick_recon(target: str) -> str:
    """
    Auto-detect target type and run quick reconnaissance.

    Automatically detects if target is: IP, email, domain, phone, or username.
    Runs appropriate checks based on detection.

    Args:
        target: Any target (IP, email, domain, phone, username)

    Returns:
        JSON with detected type and findings
    """
    result = _engine.quick_recon(target)
    return json.dumps(result, indent=2, default=str)


@tool
def shadow_investigate_person(
    username: str = None,
    email: str = None,
    phone: str = None
) -> str:
    """
    Full person investigation combining multiple data points.

    Provides comprehensive profile building from available identifiers.

    Args:
        username: Username to investigate (optional)
        email: Email to investigate (optional)
        phone: Phone to investigate (optional)

    Returns:
        JSON with comprehensive person intelligence
    """
    result = _engine.investigate_person(
        username=username,
        email=email,
        phone=phone,
        quick=True
    )
    return json.dumps(result, indent=2, default=str)


@tool
def shadow_generate_all_dorks(target: str) -> str:
    """
    Generate dorks for a target across all platforms.

    Creates Google, GitHub, and Shodan queries for comprehensive coverage.

    Args:
        target: Target (domain, company, or username)

    Returns:
        JSON with dorks for all platforms
    """
    result = _engine.generate_dorks(target)
    return json.dumps(result, indent=2)


# ============================================
# TOOL EXPORTS
# ============================================

TOOLS = [
    # Person recon
    shadow_username_hunt,
    shadow_email_recon,
    shadow_phone_lookup,

    # People search (by name)
    shadow_find_person,
    shadow_generate_usernames,
    shadow_generate_emails,
    shadow_people_search_links,

    # Profiler (build profiles with confidence)
    shadow_create_profile,
    shadow_enrich_profile,
    shadow_profile_summary,
    shadow_list_profiles,
    shadow_save_profile,
    shadow_quick_profile,

    # Image recon
    shadow_image_analyze,
    shadow_image_exif,
    shadow_image_gps,
    shadow_image_ocr,
    shadow_image_reverse_search,
    shadow_image_compare,
    shadow_image_hash,
    shadow_image_strip_metadata,

    # Domain recon
    shadow_domain_recon,
    shadow_subdomain_enum,
    shadow_tech_detect,
    shadow_whois,

    # Network recon
    shadow_ip_recon,
    shadow_geolocate,
    shadow_shodan_lookup,
    shadow_reverse_dns,

    # Dork generation
    shadow_google_dorks,
    shadow_github_dorks,
    shadow_shodan_dorks,

    # Orchestration
    shadow_quick_recon,
    shadow_investigate_person,
    shadow_generate_all_dorks,
]

TOOL_DESCRIPTIONS = {
    # Person recon
    "shadow_username_hunt": "Hunt username across 100+ platforms",
    "shadow_email_recon": "Investigate email (breaches, MX, disposable)",
    "shadow_phone_lookup": "Phone number lookup (carrier, country, type)",

    # People search (by name)
    "shadow_find_person": "Find person by name, age, city - generates dorks & links",
    "shadow_generate_usernames": "Generate possible usernames from real name",
    "shadow_generate_emails": "Generate possible emails from name",
    "shadow_people_search_links": "Get links to people search engines",

    # Profiler (build profiles over time)
    "shadow_create_profile": "Create profile with confidence ratings from name/age/location",
    "shadow_enrich_profile": "Enrich profile by hunting usernames, checking emails",
    "shadow_profile_summary": "Get quick summary of profile findings",
    "shadow_list_profiles": "List all active and saved profiles",
    "shadow_save_profile": "Save profile to disk for later",
    "shadow_quick_profile": "Create profile AND hunt top usernames immediately",

    # Image recon
    "shadow_image_analyze": "Full image analysis: EXIF, GPS, hashes, OCR",
    "shadow_image_exif": "Extract EXIF metadata (camera, dates, software)",
    "shadow_image_gps": "Extract GPS coordinates and Google Maps link",
    "shadow_image_ocr": "Extract text from image (OCR)",
    "shadow_image_reverse_search": "Get reverse image search URLs",
    "shadow_image_compare": "Compare two images for similarity",
    "shadow_image_hash": "Calculate image hashes (MD5, SHA256, perceptual)",
    "shadow_image_strip_metadata": "Remove all metadata from image",

    # Domain recon
    "shadow_domain_recon": "Full domain recon (DNS, SSL, subdomains, tech)",
    "shadow_subdomain_enum": "Enumerate subdomains via CT logs and wordlist",
    "shadow_tech_detect": "Detect website technologies (CMS, CDN, frameworks)",
    "shadow_whois": "WHOIS lookup for domain registration info",

    # Network recon
    "shadow_ip_recon": "Full IP recon (geo, Shodan, reverse DNS)",
    "shadow_geolocate": "IP geolocation (country, city, ISP, coords)",
    "shadow_shodan_lookup": "Shodan lookup (ports, vulns, hostnames)",
    "shadow_reverse_dns": "Reverse DNS - find hostnames for IP",

    # Dork generation
    "shadow_google_dorks": "Generate Google dorks for target",
    "shadow_github_dorks": "Generate GitHub search dorks",
    "shadow_shodan_dorks": "Generate Shodan search queries",

    # Orchestration
    "shadow_quick_recon": "Auto-detect target type, run quick recon",
    "shadow_investigate_person": "Full person investigation",
    "shadow_generate_all_dorks": "Generate dorks for all platforms",
}
