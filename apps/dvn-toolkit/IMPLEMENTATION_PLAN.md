# DVN Toolkit v2.1 - Implementation Plan

## Overview
This plan covers 5 major features to enhance the DVN Toolkit Android app:
1. **Identity Recon** - Meta-search tool for OSINT (NEW)
2. **Onboarding Screen** - First-time user experience
3. **Learning Paths** - Guided progression system
4. **Interactive Tutorials** - Step-by-step walkthroughs
5. **Tool Documentation** - Beginner docs for remaining ~120 tools

---

## 1. IDENTITY RECON - Meta-Search Feature

### Concept
A unified "Identity Recon" interface that orchestrates multiple OSINT tools to build comprehensive profiles. User enters ONE piece of information, and the system intelligently runs relevant tools to gather a complete picture.

### Input Types (Auto-Detected)
| Input Type | Detection Pattern | Example |
|------------|-------------------|---------|
| Email | `*@*.*` | john.doe@gmail.com |
| Username | `^[a-zA-Z0-9_-]+$` (no dots) | gh0st_hacker |
| Domain | `*.*` (no @, valid TLD) | acme.com |
| IP Address | `\d+\.\d+\.\d+\.\d+` | 192.168.1.1 |
| Phone | `^\+?[\d\s-()]+$` | +1-555-123-4567 |

### Tool Orchestration Map
```
EMAIL INPUT
├── email_osint      → Validate, breach check, provider info
├── username_search  → Extract username part, search platforms
├── google_dork      → Generate email search queries
└── social_recon     → Search social platforms

USERNAME INPUT
├── username_check   → Check 40+ platforms
├── username_search  → Extended 50+ platform search
├── social_recon     → Targeted social media search
└── google_dork      → Advanced search queries

DOMAIN INPUT
├── whois_lookup     → Registration info, registrant
├── domain_recon     → DNS, subdomains, SSL certs
├── dns_enum         → Comprehensive DNS mapping
├── banner_grab      → Service fingerprinting
├── nmap_lite        → Port scan, service detection
└── ssl_check        → Certificate details

IP ADDRESS INPUT
├── ip_geolocate     → Location, ISP, organization
├── reverse_dns      → Hostname resolution
├── nmap_lite        → Port scan, services
├── banner_grab      → Service banners
└── ssl_check        → Certificate info (if HTTPS)
```

### Architecture

#### New Files (targeting 400-500 lines, smaller is fine)
```
app/
├── screens/
│   └── identity_recon.py      # Main recon screen (~180 lines)
├── components/
│   ├── recon_input.py         # Smart input with auto-detect (~100 lines)
│   ├── recon_progress.py      # Multi-tool progress tracker (~120 lines)
│   └── profile_card.py        # Result display cards (~150 lines)
├── data/
│   ├── recon_orchestrator.py  # Tool orchestration logic (~180 lines)
│   ├── recon_profiles.py      # Profile storage/export (~120 lines)
│   └── input_detector.py      # Input type detection (~80 lines)
└── utils/
    └── result_aggregator.py   # Cross-reference results (~100 lines)
```

#### Screen Flow
```
┌─────────────────────────────────────┐
│  IDENTITY RECON                  [X]│
├─────────────────────────────────────┤
│                                     │
│  ┌─────────────────────────────┐   │
│  │ Enter target...         [?] │   │
│  └─────────────────────────────┘   │
│                                     │
│  Detected: [EMAIL] john@acme.com   │
│                                     │
│  ┌──────────────────────────────┐  │
│  │ TOOLS TO RUN:                │  │
│  │ ☑ Email OSINT    ☑ Social   │  │
│  │ ☑ Username Search ☑ Google  │  │
│  └──────────────────────────────┘  │
│                                     │
│  [QUICK SCAN]  [DEEP SCAN]  [RUN]  │
│                                     │
├─────────────────────────────────────┤
│  ⚠ LEGAL: Only scan identities     │
│    you have permission to research │
└─────────────────────────────────────┘
```

#### Results Screen
```
┌─────────────────────────────────────┐
│  ← PROFILE: john@acme.com      [⋮] │
├─────────────────────────────────────┤
│  ████████████░░░░░░░ 60%           │
│  Running: social_recon...           │
├─────────────────────────────────────┤
│                                     │
│  ┌── IDENTITY ──────────────────┐  │
│  │ Email: john@acme.com         │  │
│  │ Provider: Gmail (Google)     │  │
│  │ Valid: ✓ Deliverable         │  │
│  │ Breaches: 3 found            │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌── SOCIAL PROFILES ───────────┐  │
│  │ ✓ Twitter: @johndoe          │  │
│  │ ✓ GitHub: johndoe            │  │
│  │ ✓ LinkedIn: john-doe-123     │  │
│  │ ✗ Instagram: not found       │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌── NETWORK INFO ──────────────┐  │
│  │ Domain: acme.com             │  │
│  │ MX: mail.acme.com            │  │
│  │ Organization: ACME Corp      │  │
│  └──────────────────────────────┘  │
│                                     │
├─────────────────────────────────────┤
│  [SAVE]  [EXPORT]  [NEW SEARCH]    │
└─────────────────────────────────────┘
```

#### Data Model - Profile
```python
{
    "id": "uuid",
    "created": "2026-01-17T12:00:00",
    "input": "john@acme.com",
    "input_type": "email",
    "results": {
        "email_osint": {
            "status": "complete",
            "data": {...},
            "timestamp": "..."
        },
        "username_search": {...},
        ...
    },
    "summary": {
        "identity": {...},
        "social": {...},
        "network": {...},
        "technical": {...}
    },
    "cross_references": [
        {"source": "email_osint", "target": "social_recon", "link": "username match"}
    ]
}
```

---

## 2. ONBOARDING SCREEN

### Purpose
Guide first-time users through the app, explain what it does, and help them get started safely.

### Screen Flow (4 slides)
```
SLIDE 1: Welcome
┌─────────────────────────────────────┐
│                                     │
│         ☠ DVN TOOLKIT              │
│                                     │
│    130+ Security & Utility Tools    │
│         in your pocket              │
│                                     │
│  "Your Swiss Army Knife for        │
│   digital reconnaissance"           │
│                                     │
│         ● ○ ○ ○                    │
│                                     │
│            [NEXT →]                 │
└─────────────────────────────────────┘

SLIDE 2: Categories
┌─────────────────────────────────────┐
│         TOOL CATEGORIES             │
│                                     │
│  ☠ Offensive - Pentest tools       │
│  🔐 Security - Defensive tools     │
│  ⇄ Network - Discovery & recon     │
│  🔍 OSINT - Intelligence gather    │
│  📱 Android - Mobile testing       │
│                                     │
│         ○ ● ○ ○                    │
│                                     │
│     [← BACK]    [NEXT →]           │
└─────────────────────────────────────┘

SLIDE 3: Safety Warning
┌─────────────────────────────────────┐
│         ⚠ IMPORTANT                │
│                                     │
│  These tools are powerful.         │
│  Use them responsibly:             │
│                                     │
│  ✓ Only scan YOUR systems          │
│  ✓ Get PERMISSION first            │
│  ✓ Use for LEARNING                │
│  ✓ CTFs and authorized testing     │
│                                     │
│  ✗ Never scan without consent      │
│  ✗ Don't use for malicious acts    │
│                                     │
│         ○ ○ ● ○                    │
│                                     │
│     [← BACK]    [NEXT →]           │
└─────────────────────────────────────┘

SLIDE 4: Get Started
┌─────────────────────────────────────┐
│         CHOOSE YOUR PATH           │
│                                     │
│  What's your experience level?     │
│                                     │
│  ┌────────────────────────────┐    │
│  │  ⭐ BEGINNER               │    │
│  │  New to security tools     │    │
│  └────────────────────────────┘    │
│                                     │
│  ┌────────────────────────────┐    │
│  │  ⭐⭐ INTERMEDIATE         │    │
│  │  Some CLI experience       │    │
│  └────────────────────────────┘    │
│                                     │
│  ┌────────────────────────────┐    │
│  │  ⭐⭐⭐ ADVANCED           │    │
│  │  Experienced pentester     │    │
│  └────────────────────────────┘    │
│                                     │
│         ○ ○ ○ ●                    │
│                                     │
│          [GET STARTED]              │
└─────────────────────────────────────┘
```

### New Files
```
app/screens/onboarding.py  (~150 lines)
```

### Integration
- Check `settings.json` for `onboarding_complete: false`
- Show onboarding on first launch
- Save skill level to settings
- Show appropriate tool recommendations

---

## 3. LEARNING PATHS

### Concept
Structured learning journeys that guide users from basics to advanced techniques.

### Paths
```
PATH 1: Network Fundamentals
├── Lesson 1: What is an IP address?
│   └── Tool: ip_geolocate (look up your own IP)
├── Lesson 2: DNS - The internet's phonebook
│   └── Tool: dns_lookup (query popular domains)
├── Lesson 3: Ports - Doors to services
│   └── Tool: portscanner (scan localhost)
├── Lesson 4: Network mapping
│   └── Tool: ping_sweep (scan home network)
└── Final Challenge: Map your local network

PATH 2: OSINT Basics
├── Lesson 1: What is OSINT?
│   └── Tool: google_dork (search techniques)
├── Lesson 2: Username hunting
│   └── Tool: username_check (check your own username)
├── Lesson 3: Email intelligence
│   └── Tool: email_osint (analyze your email)
├── Lesson 4: Domain research
│   └── Tool: whois_lookup (query domains)
└── Final Challenge: Build a profile (authorized)

PATH 3: Web Security
├── Lesson 1: HTTP headers & fingerprinting
│   └── Tool: header_analyzer
├── Lesson 2: Technology detection
│   └── Tool: techdetect
├── Lesson 3: Directory enumeration
│   └── Tool: web_fuzzer (on test sites)
├── Lesson 4: SQL injection basics
│   └── Tool: sqli_scanner (on vulnerable labs)
└── Final Challenge: Test a CTF site

PATH 4: Android Security
├── Lesson 1: ADB fundamentals
│   └── Tool: adb_toolkit
├── Lesson 2: App permissions
│   └── Tool: app_permissions
├── Lesson 3: APK analysis
│   └── Tool: apk_analyzer
└── Final Challenge: Audit an app
```

### Screen Design
```
┌─────────────────────────────────────┐
│  ← LEARNING PATHS              [?] │
├─────────────────────────────────────┤
│                                     │
│  YOUR PROGRESS                      │
│  ████████░░░░░░░░░░░░ 40%          │
│                                     │
│  ┌── NETWORK FUNDAMENTALS ──────┐  │
│  │ ⭐ Beginner | 4 lessons      │  │
│  │ Progress: 2/4 complete       │  │
│  │ [CONTINUE]                   │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌── OSINT BASICS ──────────────┐  │
│  │ ⭐ Beginner | 4 lessons      │  │
│  │ Progress: 0/4 complete       │  │
│  │ [START]                      │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌── WEB SECURITY ──────────────┐  │
│  │ ⭐⭐ Intermediate | 4 lessons │  │
│  │ 🔒 Complete OSINT first      │  │
│  └──────────────────────────────┘  │
│                                     │
├─────────────────────────────────────┤
│  [H] [*] [📚] [S]                  │
└─────────────────────────────────────┘
```

### New Files
```
app/
├── screens/
│   ├── learning_paths.py     # Path list screen (~150 lines)
│   └── lesson_view.py        # Individual lesson (~180 lines)
├── data/
│   ├── paths_registry.py     # Path/lesson definitions (~200 lines)
│   └── progress_tracker.py   # User progress storage (~100 lines)
```

---

## 4. INTERACTIVE TUTORIALS

### Concept
Step-by-step guided tutorials that walk users through tool usage with real examples.

### Tutorial Structure
```python
{
    "id": "portscanner_intro",
    "tool_id": "portscanner",
    "title": "Your First Port Scan",
    "difficulty": "beginner",
    "estimated_time": "5 min",
    "steps": [
        {
            "type": "explanation",
            "content": "A port scanner checks which 'doors' are open on a computer...",
            "visual": "port_diagram"
        },
        {
            "type": "input_guide",
            "field": "target",
            "instruction": "Enter 'localhost' to scan your own machine",
            "highlight": True,
            "validation": "localhost|127.0.0.1"
        },
        {
            "type": "input_guide",
            "field": "ports",
            "instruction": "Enter '1-100' to scan the first 100 ports",
            "default": "1-100"
        },
        {
            "type": "run_prompt",
            "message": "Ready to run your first scan!",
            "button_text": "RUN SCAN"
        },
        {
            "type": "output_explanation",
            "patterns": [
                {"match": "OPEN", "explain": "This port is accepting connections"},
                {"match": "CLOSED", "explain": "This port rejected the connection"},
                {"match": "FILTERED", "explain": "A firewall is blocking this port"}
            ]
        },
        {
            "type": "summary",
            "content": "You just discovered which services are running on your machine!",
            "next_steps": ["Try scanning port 22 (SSH)", "Learn about common ports"]
        }
    ]
}
```

### UI Overlay Design
```
┌─────────────────────────────────────┐
│  TUTORIAL: Your First Port Scan    │
│  Step 2 of 6                        │
├─────────────────────────────────────┤
│                                     │
│  ┌─ TOOL DETAIL (dimmed) ────────┐ │
│  │                               │ │
│  │  Target: [localhost    ]  ←───┼─┼─ HIGHLIGHTED
│  │          ↑                    │ │
│  │  ┌────────────────────────┐   │ │
│  │  │ Enter 'localhost' to   │   │ │
│  │  │ scan your own machine  │   │ │
│  │  │                        │   │ │
│  │  │     [GOT IT]           │   │ │
│  │  └────────────────────────┘   │ │
│  │                               │ │
│  │  Ports: [          ]          │ │
│  │                               │ │
│  └───────────────────────────────┘ │
│                                     │
│  [← BACK]  [SKIP TUTORIAL]  [→]    │
└─────────────────────────────────────┘
```

### New Files
```
app/
├── components/
│   ├── tutorial_overlay.py   # Tutorial UI overlay (~150 lines)
│   └── step_renderer.py      # Render different step types (~120 lines)
├── data/
│   └── tutorials_registry.py # Tutorial definitions (~200 lines)
```

---

## 5. TOOL DOCUMENTATION STRATEGY

### Current State
- 7 tools have full beginner docs
- ~120 tools need documentation

### Documentation Template
```python
'docs': {
    'short_desc': 'One-line description',
    'full_desc': 'Multi-paragraph explanation...',
    'concept_explanation': {
        'title': 'What is [CONCEPT]?',
        'simple': 'Imagine [ANALOGY]...',
        'technical': 'Technical details...'
    },
    'when_to_use': ['Use case 1', 'Use case 2'],
    'real_world_example': 'Scenario: You want to...',
    'expected_output': 'You will see...',
    'warnings': ['Warning 1'],
    'prerequisites': ['Requirement 1'],
    'step_by_step': [
        {'step': 1, 'title': '...', 'instruction': '...', 'tip': '...'}
    ],
    'common_mistakes': [
        {'mistake': '...', 'fix': '...'}
    ],
    'glossary': [
        {'term': 'Term', 'definition': 'Def'}
    ]
}
```

### Batch Documentation Plan
Group tools by category and document in phases:

**Phase 1: High-Priority (20 tools)**
- Network basics: dns_lookup, ping_sweep, arp_scan, whois_lookup, ip_geolocate
- Security essentials: hasher, encoder, creds, password_gen
- OSINT core: username_check, social_recon, google_dork, email_osint
- Offensive intro: nmap_lite, web_fuzzer, dns_enum

**Phase 2: Common Tools (40 tools)**
- Network: all remaining network/ tools
- File utilities: pdf_tools, archive_manager, bulk_rename
- System: sysinfo, processes, diskusage

**Phase 3: Advanced Tools (40 tools)**
- Offensive: sqli_scanner, xss_scanner, lfi_scanner, bruteforce
- Android: adb_toolkit, apk_analyzer
- Pentest: privesc_checker, persistence_checker

**Phase 4: Specialized (20 tools)**
- Crypto, forensics, media tools
- Fun/productivity tools

---

## Implementation Order

### Phase 1: Foundation (Identity Recon Core)
1. `input_detector.py` - Input type detection
2. `recon_orchestrator.py` - Tool orchestration logic
3. `identity_recon.py` - Main screen
4. `recon_input.py` - Smart input component
5. `recon_progress.py` - Progress tracking
6. Integration with dashboard

### Phase 2: Results & Storage
1. `profile_card.py` - Result display
2. `result_aggregator.py` - Cross-reference logic
3. `recon_profiles.py` - Profile storage
4. Export functionality (JSON, text)

### Phase 3: Onboarding
1. `onboarding.py` - 4-slide onboarding
2. Settings integration
3. Skill level persistence

### Phase 4: Learning System
1. `paths_registry.py` - Path definitions
2. `progress_tracker.py` - Progress storage
3. `learning_paths.py` - Path list screen
4. `lesson_view.py` - Lesson display

### Phase 5: Tutorials
1. `tutorials_registry.py` - Tutorial definitions
2. `tutorial_overlay.py` - UI overlay
3. `step_renderer.py` - Step rendering
4. Integration with tool_detail.py

### Phase 6: Documentation
1. Batch document tools by category
2. Update tool_registry_full.py
3. Add documentation for all 120+ tools

---

## Dashboard Integration

### Add Identity Recon Button
```
Header: DVN TOOLKIT [T] [S]
         ↓
┌────────────────────────────────┐
│  🔍 IDENTITY RECON            │
│  Search email/username/domain  │
│  [START RECON →]               │
└────────────────────────────────┘
         ↓
Search bar: [Search tools...]
```

### Add Learning Paths to Bottom Nav
```
[H]     [*]     [📚]     [S]
Home    Favs    Learn    Settings
```

---

## File Size Compliance

All new files should target 400-500 lines (smaller is fine, larger negotiable if justified):
- Screens: 150-400 lines each
- Components: 100-300 lines each
- Data/Logic: 100-400 lines each

Split large logic into multiple focused modules.

---

## Testing Checklist

- [ ] Input detection works for all types
- [ ] Tool orchestration runs tools correctly
- [ ] Results aggregate properly
- [ ] Profile save/load works
- [ ] Export generates valid files
- [ ] Onboarding flows correctly
- [ ] Learning progress persists
- [ ] Tutorials highlight correct fields
- [ ] All tools have documentation
- [ ] APK builds successfully
- [ ] Works on Android device

---

*Created: January 17, 2026*
*DVN Toolkit v2.1 Planning Document*
