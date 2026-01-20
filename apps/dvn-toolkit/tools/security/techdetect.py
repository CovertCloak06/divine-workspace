#!/usr/bin/env python3
"""
Tech Stack Detector - Identify technologies used by a website
Usage: techdetect <url>
"""

import re
import ssl
import json
import argparse
from urllib.request import urlopen, Request
from urllib.error import URLError

CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

# Technology signatures
SIGNATURES = {
    'Frameworks': {
        'React': [r'react\.js', r'react\.min\.js', r'react-dom', r'data-reactroot', r'__REACT_DEVTOOLS'],
        'Vue.js': [r'vue\.js', r'vue\.min\.js', r'data-v-[a-f0-9]', r'__VUE__'],
        'Angular': [r'angular\.js', r'angular\.min\.js', r'ng-app', r'ng-controller', r'\[ngClass\]'],
        'jQuery': [r'jquery\.js', r'jquery\.min\.js', r'jquery-[0-9]'],
        'Bootstrap': [r'bootstrap\.css', r'bootstrap\.min\.css', r'class="[^"]*\bcontainer\b[^"]*"'],
        'Tailwind': [r'tailwind', r'class="[^"]*\b(flex|grid|p-\d|m-\d|text-\w+)\b'],
        'Next.js': [r'__NEXT_DATA__', r'_next/static'],
        'Nuxt.js': [r'__NUXT__', r'_nuxt/'],
        'Svelte': [r'svelte', r'__svelte'],
        'Django': [r'csrfmiddlewaretoken', r'__admin_media_prefix__'],
        'Flask': [r'Werkzeug', r'flask'],
        'Laravel': [r'laravel', r'csrf-token'],
        'Ruby on Rails': [r'csrf-token.*rails', r'data-turbo'],
        'Express': [r'X-Powered-By.*Express'],
        'WordPress': [r'wp-content', r'wp-includes', r'/wp-json/', r'wordpress'],
        'Drupal': [r'Drupal', r'/sites/default/', r'drupal\.js'],
        'Joomla': [r'Joomla', r'/components/', r'/modules/'],
        'Shopify': [r'cdn\.shopify', r'Shopify\.theme'],
        'Wix': [r'wix\.com', r'wixstatic'],
        'Squarespace': [r'squarespace', r'static\.squarespace'],
    },
    'Server': {
        'Apache': [r'Server.*Apache', r'apache'],
        'Nginx': [r'Server.*nginx', r'nginx'],
        'IIS': [r'Server.*IIS', r'X-Powered-By.*ASP'],
        'Cloudflare': [r'cloudflare', r'cf-ray', r'__cfduid'],
        'AWS': [r'AmazonS3', r'x-amz-', r'amazonaws\.com'],
        'Google Cloud': [r'x-goog-', r'storage\.googleapis'],
        'Vercel': [r'x-vercel', r'vercel\.app'],
        'Netlify': [r'netlify', r'x-nf-'],
        'Heroku': [r'heroku', r'herokuapp'],
        'DigitalOcean': [r'digitalocean'],
    },
    'Security': {
        'Cloudflare WAF': [r'cloudflare', r'cf-ray'],
        'Sucuri': [r'sucuri', r'x-sucuri'],
        'Akamai': [r'akamai', r'x-akamai'],
        'Imperva': [r'incapsula', r'imperva'],
        'AWS WAF': [r'awswaf', r'x-amzn-waf'],
        'ModSecurity': [r'mod_security', r'modsecurity'],
    },
    'Analytics': {
        'Google Analytics': [r'google-analytics\.com', r'ga\(', r'gtag\(', r'_ga='],
        'Google Tag Manager': [r'googletagmanager\.com', r'GTM-'],
        'Facebook Pixel': [r'connect\.facebook\.net', r'fbq\('],
        'Hotjar': [r'hotjar\.com', r'_hjid'],
        'Mixpanel': [r'mixpanel\.com', r'mixpanel'],
        'Segment': [r'segment\.com', r'analytics\.js'],
        'Plausible': [r'plausible\.io'],
        'Matomo': [r'matomo', r'piwik'],
    },
    'CMS/Platforms': {
        'WordPress': [r'wp-content', r'wp-includes'],
        'Ghost': [r'ghost\.org', r'ghost-'],
        'Webflow': [r'webflow\.com'],
        'Contentful': [r'contentful'],
        'Strapi': [r'strapi'],
        'Sanity': [r'sanity\.io'],
    },
    'E-commerce': {
        'Shopify': [r'cdn\.shopify', r'Shopify'],
        'WooCommerce': [r'woocommerce', r'wc-'],
        'Magento': [r'magento', r'mage/'],
        'BigCommerce': [r'bigcommerce'],
        'PrestaShop': [r'prestashop'],
    },
    'JavaScript': {
        'Lodash': [r'lodash'],
        'Moment.js': [r'moment\.js', r'moment\.min\.js'],
        'Axios': [r'axios'],
        'Socket.io': [r'socket\.io'],
        'Three.js': [r'three\.js', r'three\.min\.js'],
        'D3.js': [r'd3\.js', r'd3\.min\.js'],
        'Chart.js': [r'chart\.js'],
        'GSAP': [r'gsap', r'TweenMax', r'TweenLite'],
    }
}

def fetch_page(url):
    """Fetch page content and headers"""
    if not url.startswith('http'):
        url = 'https://' + url

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Accept': 'text/html,application/xhtml+xml',
        })

        with urlopen(req, timeout=15, context=ctx) as resp:
            return {
                'status': resp.status,
                'headers': dict(resp.headers),
                'body': resp.read().decode('utf-8', errors='replace'),
                'url': resp.url
            }
    except Exception as e:
        return {'error': str(e)}

def detect_technologies(data):
    """Detect technologies from response"""
    if 'error' in data:
        return {}

    detected = {}
    headers_str = json.dumps(data['headers'])
    body = data['body']
    combined = headers_str + body

    for category, techs in SIGNATURES.items():
        found = []
        for tech, patterns in techs.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    if tech not in found:
                        found.append(tech)
                    break
        if found:
            detected[category] = found

    return detected

def analyze_headers(headers):
    """Analyze security and other headers"""
    analysis = []

    # Security headers
    security_headers = {
        'Strict-Transport-Security': 'HSTS enabled',
        'Content-Security-Policy': 'CSP configured',
        'X-Frame-Options': 'Clickjacking protection',
        'X-Content-Type-Options': 'MIME sniffing prevention',
        'X-XSS-Protection': 'XSS filter',
        'Referrer-Policy': 'Referrer control',
    }

    for header, desc in security_headers.items():
        found = any(h.lower() == header.lower() for h in headers)
        analysis.append((header, found, desc))

    return analysis

def main():
    parser = argparse.ArgumentParser(description='Tech Stack Detector')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--json', '-j', action='store_true', help='JSON output')
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}Tech Stack Detector{RESET}")
    print(f"Target: {args.url}\n")

    data = fetch_page(args.url)

    if 'error' in data:
        print(f"{RED}Error: {data['error']}{RESET}")
        return

    print(f"{DIM}Status: {data['status']} | URL: {data['url']}{RESET}\n")

    detected = detect_technologies(data)

    if args.json:
        print(json.dumps(detected, indent=2))
        return

    if not detected:
        print(f"{YELLOW}No technologies detected{RESET}")
    else:
        for category, techs in detected.items():
            print(f"{BOLD}{category}:{RESET}")
            for tech in techs:
                print(f"  {GREEN}✓{RESET} {tech}")
            print()

    # Security analysis
    print(f"{BOLD}Security Headers:{RESET}")
    for header, found, desc in analyze_headers(data['headers']):
        status = f"{GREEN}✓{RESET}" if found else f"{RED}✗{RESET}"
        print(f"  {status} {header}")

    # Server info
    server = data['headers'].get('Server', 'Unknown')
    powered = data['headers'].get('X-Powered-By', 'Unknown')
    print(f"\n{BOLD}Server Info:{RESET}")
    print(f"  Server: {server}")
    if powered != 'Unknown':
        print(f"  Powered By: {powered}")

    print()

if __name__ == '__main__':
    main()
