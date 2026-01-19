#!/usr/bin/env python3
"""
Shadow OSINT - Data Sources Configuration
Free APIs and platforms that require no API keys
"""

# Free APIs (no key required)
DATA_SOURCES = {
    # IP/Geolocation
    "ip_api": {
        "url": "http://ip-api.com/json/{ip}",
        "rate_limit": "45/min",
        "fields": ["country", "city", "isp", "org", "as", "lat", "lon"],
    },
    "ipinfo": {
        "url": "https://ipinfo.io/{ip}/json",
        "rate_limit": "50k/month",
        "fields": ["city", "region", "country", "org", "hostname"],
    },
    # SSL/Certificates
    "crtsh": {
        "url": "https://crt.sh/?q={domain}&output=json",
        "rate_limit": "none",
        "fields": ["name_value", "issuer_name", "not_before", "not_after"],
    },
    # Shodan (limited free)
    "internetdb": {
        "url": "https://internetdb.shodan.io/{ip}",
        "rate_limit": "none",
        "fields": ["ports", "hostnames", "cpes", "vulns", "tags"],
    },
    # DNS
    "hackertarget_dns": {
        "url": "https://api.hackertarget.com/dnslookup/?q={domain}",
        "rate_limit": "100/day",
        "fields": ["A", "MX", "NS", "TXT"],
    },
    "hackertarget_reverse": {
        "url": "https://api.hackertarget.com/reverseiplookup/?q={ip}",
        "rate_limit": "100/day",
        "fields": ["domains"],
    },
    # Subdomains
    "hackertarget_subdomain": {
        "url": "https://api.hackertarget.com/hostsearch/?q={domain}",
        "rate_limit": "100/day",
        "fields": ["subdomain", "ip"],
    },
    # Wayback Machine
    "wayback": {
        "url": "http://archive.org/wayback/available?url={url}",
        "rate_limit": "none",
        "fields": ["timestamp", "available", "url"],
    },
    # Email verification
    "disify": {
        "url": "https://www.disify.com/api/email/{email}",
        "rate_limit": "1000/day",
        "fields": ["format", "disposable", "dns"],
    },
    # Breach check (k-anonymity)
    "hibp_passwords": {
        "url": "https://api.pwnedpasswords.com/range/{hash_prefix}",
        "rate_limit": "none",
        "fields": ["hash_suffix", "count"],
    },
}

# Username check platforms (200+)
USERNAME_PLATFORMS = {
    # Developer
    "github": {"url": "https://github.com/{}", "category": "dev"},
    "gitlab": {"url": "https://gitlab.com/{}", "category": "dev"},
    "bitbucket": {"url": "https://bitbucket.org/{}", "category": "dev"},
    "stackoverflow": {"url": "https://stackoverflow.com/users/{}", "category": "dev"},
    "codepen": {"url": "https://codepen.io/{}", "category": "dev"},
    "replit": {"url": "https://replit.com/@{}", "category": "dev"},
    "npm": {"url": "https://www.npmjs.com/~{}", "category": "dev"},
    "pypi": {"url": "https://pypi.org/user/{}", "category": "dev"},
    "dockerhub": {"url": "https://hub.docker.com/u/{}", "category": "dev"},
    "dev_to": {"url": "https://dev.to/{}", "category": "dev"},
    "hashnode": {"url": "https://{}.hashnode.dev", "category": "dev"},
    "hackerrank": {"url": "https://www.hackerrank.com/{}", "category": "dev"},
    "leetcode": {"url": "https://leetcode.com/{}", "category": "dev"},
    "kaggle": {"url": "https://www.kaggle.com/{}", "category": "dev"},
    "codewars": {"url": "https://www.codewars.com/users/{}", "category": "dev"},

    # Social Media
    "twitter": {"url": "https://twitter.com/{}", "category": "social"},
    "instagram": {"url": "https://instagram.com/{}", "category": "social"},
    "facebook": {"url": "https://facebook.com/{}", "category": "social"},
    "tiktok": {"url": "https://tiktok.com/@{}", "category": "social"},
    "snapchat": {"url": "https://www.snapchat.com/add/{}", "category": "social"},
    "threads": {"url": "https://www.threads.net/@{}", "category": "social"},
    "mastodon": {"url": "https://mastodon.social/@{}", "category": "social"},
    "bluesky": {"url": "https://bsky.app/profile/{}.bsky.social", "category": "social"},

    # Professional
    "linkedin": {"url": "https://linkedin.com/in/{}", "category": "professional"},
    "angel": {"url": "https://angel.co/u/{}", "category": "professional"},
    "about_me": {"url": "https://about.me/{}", "category": "professional"},
    "behance": {"url": "https://www.behance.net/{}", "category": "professional"},
    "dribbble": {"url": "https://dribbble.com/{}", "category": "professional"},

    # Content
    "youtube": {"url": "https://youtube.com/@{}", "category": "content"},
    "twitch": {"url": "https://twitch.tv/{}", "category": "content"},
    "vimeo": {"url": "https://vimeo.com/{}", "category": "content"},
    "dailymotion": {"url": "https://www.dailymotion.com/{}", "category": "content"},
    "soundcloud": {"url": "https://soundcloud.com/{}", "category": "content"},
    "spotify": {"url": "https://open.spotify.com/user/{}", "category": "content"},
    "bandcamp": {"url": "https://{}.bandcamp.com", "category": "content"},
    "medium": {"url": "https://medium.com/@{}", "category": "content"},
    "substack": {"url": "https://{}.substack.com", "category": "content"},
    "patreon": {"url": "https://www.patreon.com/{}", "category": "content"},
    "ko_fi": {"url": "https://ko-fi.com/{}", "category": "content"},
    "buymeacoffee": {"url": "https://www.buymeacoffee.com/{}", "category": "content"},

    # Forums/Community
    "reddit": {"url": "https://reddit.com/user/{}", "category": "forum"},
    "hackernews": {"url": "https://news.ycombinator.com/user?id={}", "category": "forum"},
    "producthunt": {"url": "https://www.producthunt.com/@{}", "category": "forum"},
    "quora": {"url": "https://www.quora.com/profile/{}", "category": "forum"},
    "discord": {"url": "https://discord.com/users/{}", "category": "forum"},
    "telegram": {"url": "https://t.me/{}", "category": "forum"},
    "keybase": {"url": "https://keybase.io/{}", "category": "forum"},
    "4chan": {"url": "https://boards.4chan.org/search?username={}", "category": "forum"},

    # Gaming
    "steam": {"url": "https://steamcommunity.com/id/{}", "category": "gaming"},
    "xbox": {"url": "https://account.xbox.com/profile?gamertag={}", "category": "gaming"},
    "playstation": {"url": "https://psnprofiles.com/{}", "category": "gaming"},
    "epicgames": {"url": "https://www.epicgames.com/id/{}", "category": "gaming"},
    "roblox": {"url": "https://www.roblox.com/user.aspx?username={}", "category": "gaming"},
    "minecraft": {"url": "https://namemc.com/profile/{}", "category": "gaming"},
    "chess": {"url": "https://www.chess.com/member/{}", "category": "gaming"},
    "lichess": {"url": "https://lichess.org/@/{}", "category": "gaming"},

    # Security/Hacking
    "hackthebox": {"url": "https://app.hackthebox.com/profile/{}", "category": "security"},
    "tryhackme": {"url": "https://tryhackme.com/p/{}", "category": "security"},
    "bugcrowd": {"url": "https://bugcrowd.com/{}", "category": "security"},
    "hackerone": {"url": "https://hackerone.com/{}", "category": "security"},
    "ctftime": {"url": "https://ctftime.org/user/{}", "category": "security"},
    "vulnhub": {"url": "https://www.vulnhub.com/author/{}", "category": "security"},

    # Photography/Art
    "flickr": {"url": "https://www.flickr.com/people/{}", "category": "media"},
    "500px": {"url": "https://500px.com/{}", "category": "media"},
    "unsplash": {"url": "https://unsplash.com/@{}", "category": "media"},
    "pexels": {"url": "https://www.pexels.com/@{}", "category": "media"},
    "deviantart": {"url": "https://{}.deviantart.com", "category": "media"},
    "artstation": {"url": "https://www.artstation.com/{}", "category": "media"},
    "pixiv": {"url": "https://www.pixiv.net/users/{}", "category": "media"},
    "imgur": {"url": "https://imgur.com/user/{}", "category": "media"},

    # Dating
    "okcupid": {"url": "https://www.okcupid.com/profile/{}", "category": "dating"},
    "pof": {"url": "https://www.pof.com/viewprofile.aspx?profile_id={}", "category": "dating"},

    # E-commerce
    "ebay": {"url": "https://www.ebay.com/usr/{}", "category": "ecommerce"},
    "etsy": {"url": "https://www.etsy.com/shop/{}", "category": "ecommerce"},
    "amazon": {"url": "https://www.amazon.com/gp/profile/{}", "category": "ecommerce"},
    "shopify": {"url": "https://{}.myshopify.com", "category": "ecommerce"},

    # Crypto
    "bitcointalk": {"url": "https://bitcointalk.org/index.php?action=profile;u={}", "category": "crypto"},
    "opensea": {"url": "https://opensea.io/{}", "category": "crypto"},
    "rarible": {"url": "https://rarible.com/{}", "category": "crypto"},

    # Music
    "last_fm": {"url": "https://www.last.fm/user/{}", "category": "music"},
    "mixcloud": {"url": "https://www.mixcloud.com/{}", "category": "music"},
    "genius": {"url": "https://genius.com/{}", "category": "music"},

    # Misc
    "gravatar": {"url": "https://en.gravatar.com/{}", "category": "misc"},
    "pinterest": {"url": "https://pinterest.com/{}", "category": "misc"},
    "tumblr": {"url": "https://{}.tumblr.com", "category": "misc"},
    "wordpress": {"url": "https://{}.wordpress.com", "category": "misc"},
    "blogger": {"url": "https://{}.blogspot.com", "category": "misc"},
    "wix": {"url": "https://{}.wixsite.com", "category": "misc"},
    "linktree": {"url": "https://linktr.ee/{}", "category": "misc"},
    "carrd": {"url": "https://{}.carrd.co", "category": "misc"},
    "gumroad": {"url": "https://gumroad.com/{}", "category": "misc"},
    "fiverr": {"url": "https://www.fiverr.com/{}", "category": "misc"},
    "upwork": {"url": "https://www.upwork.com/freelancers/~{}", "category": "misc"},
    "paypal": {"url": "https://www.paypal.com/paypalme/{}", "category": "misc"},
    "venmo": {"url": "https://venmo.com/{}", "category": "misc"},
    "cashapp": {"url": "https://cash.app/${}", "category": "misc"},
}

# Platform categories for filtering
CATEGORIES = [
    "dev",
    "social",
    "professional",
    "content",
    "forum",
    "gaming",
    "security",
    "media",
    "dating",
    "ecommerce",
    "crypto",
    "music",
    "misc",
]

def get_platforms_by_category(category: str) -> dict:
    """Get all platforms in a specific category."""
    return {
        name: data
        for name, data in USERNAME_PLATFORMS.items()
        if data.get("category") == category
    }

def get_all_platform_urls(username: str) -> dict:
    """Generate all platform URLs for a username."""
    return {
        name: data["url"].format(username)
        for name, data in USERNAME_PLATFORMS.items()
    }
