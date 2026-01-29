# PAGalaxyLab Security Research - Complete Repository Index

**Organization:** PAGalaxyLab
**Focus Areas:** Android security, embedded systems, reverse engineering
**Analysis Date:** 2026-01-28

---

## Overview

PAGalaxyLab is a security research organization known for:
1. **YAHFA** - Android ART hooking framework (used by PREDATOR spyware)
2. **VxHunter** - VxWorks firmware analysis toolkit
3. **Vulnerability Research** - IoT and router security
4. **Reverse Engineering Tools** - Ghidra scripts and analysis utilities

---

## Repositories Analyzed

### 1. YAHFA (Yet Another Hook Framework for ART)

**URL:** https://github.com/PAGalaxyLab/YAHFA
**License:** GNU GPL V3
**Language:** Java + C/C++
**Purpose:** Android Runtime (ART) method hooking

**Key Features:**
- Hook Java methods at ART level
- Works on Android 7.0 - 12+ (API 24-31+)
- Supports x86, x86_64, armeabi-v7a, arm64-v8a
- No root required (if injected into app process)
- Used by VirtualHook for non-root hooking

**Use in PREDATOR Spyware:**
- Application hiding (hook PackageManager APIs)
- Filter installed apps list
- Prevent boot execution via broadcast hooking
- Embed DEX file with hooks, load via InMemoryDexClassLoader

**Core API:**
```java
HookMain.backupAndHook(Method target, Method hook, Method backup);
```

**Documentation:**
- [YAHFA_APP_HIDING_ANALYSIS.md](YAHFA_APP_HIDING_ANALYSIS.md) (22KB)
- Detailed analysis of PREDATOR's application hiding mechanism
- ArtMethod structure modification
- Memory layout and detection methods

**Relevance to Specter:**
- ❌ Requires process injection into system_server (needs kernel exploit)
- ℹ️ Educational reference for understanding advanced hiding techniques
- ℹ️ Shows state-of-the-art ART hooking capabilities

---

### 2. VxHunter (VxWorks Firmware Analysis Toolkit)

**URL:** https://github.com/PAGalaxyLab/vxhunter
**License:** MIT
**Language:** Python
**Purpose:** Analyze VxWorks-based embedded devices (routers, switches, ICS)

**Key Features:**
- Firmware analysis plugins for IDA Pro, Ghidra, Radare2
- Fix function names with symbol tables
- Analyze firmware loading addresses
- Serial debugger for runtime debugging
- Memory read/write via VxWorks command line
- Conditional breakpoints with Python

**Supported Platforms:**
- IDA Pro 7.x
- Ghidra 9.x
- Radare2

**Tested Firmware:**
- Schneider 140NOE77101 (Ethernet TCP/IP module)
- Siemens SCALANCE-X208/X216/X308 (Industrial switches)
- Hirschmann PowerMICE (Industrial ETHERNET switch)
- TP-Link routers (CVE-2018-19528 example)

**Components:**

#### Firmware Analysis Tools
```
firmware_tools/
├── vxhunter_ida_py3.py         # IDA Pro plugin
├── ghidra/
│   ├── vxhunter_firmware_init.py    # Load firmware
│   ├── vxhunter_analysis.py         # Find hardcoded accounts/services
│   └── vxhunter_utility/            # Helper functions
├── vxhunter_r2_py3.py          # Radare2 plugin
└── extract_tools/
    └── cisco_firmware_extractor.py  # Cisco firmware extraction
```

#### VxSerial Debugger (Beta)
```python
# Capabilities:
- Memory read/write
- Conditional breakpoints (Python-based)
- Task status viewer (stacks, registers)
- VxWorks struct viewer (netpool, clBlk, etc.)
- Dynamic shellcode injection (keystone-engine)
```

**Example Use Case:**
Debugging CVE-2018-19528 on TP-Link TL-WR886N-V7 router

**Relevance to Specter:**
- ❌ Not directly applicable (VxWorks vs Android)
- ℹ️ Shows PAGalaxyLab's expertise in embedded systems
- ℹ️ Firmware analysis techniques for IoT devices
- ℹ️ Could be relevant for router/gateway exploitation research

---

### 3. Ghidra Scripts

**URL:** https://github.com/PAGalaxyLab/ghidra_scripts
**License:** Apache 2.0
**Language:** Python
**Purpose:** Ghidra reverse engineering automation scripts

**Contents:**

#### OLLVM Deobfuscation
```
ollvm_deobf_fla.py
```
- Deobfuscate OLLVM-protected binaries
- Control flow flattening removal
- Simplifies reverse engineering of protected code

#### DEX Parameter Tracing
```
DexFile_Parameter_Trace.py
```
- Trace DEX file parameters
- Android APK analysis
- Method parameter flow analysis

#### Objective-C Analysis
```
AnalyzeOCMsgSend.py
```
- Analyze Objective-C message send calls
- iOS binary reverse engineering
- Method name recovery

#### Function Call Tracing
```
trace_function_call_parm_value.py
```
- Trace function call parameter values
- Dynamic analysis support
- Debugging assistance

#### Router-Specific Analysis
```
wr886nv7_rename_function_with_error_print.py
```
- TP-Link WR886N v7 router analysis
- Function naming based on error messages
- Firmware reverse engineering

**Relevance to Specter:**
- ℹ️ DEX tracing useful for Android APK analysis
- ℹ️ OLLVM deobfuscation if encountering obfuscated malware
- ℹ️ General reverse engineering productivity tools

---

### 4. VulInfo (Vulnerability Research Database)

**URL:** https://github.com/PAGalaxyLab/VulInfo
**License:** MIT
**Purpose:** Public vulnerability disclosure repository

**Contents:**

#### ASUS Router Vulnerabilities
```
ASUS/
├── RT-AC68U/
├── RT-AX88U/
└── [Multiple router models]
```

#### D-Link Router Vulnerabilities
```
D-Link/
└── DIR846/
    ├── Auth bypass (change admin password)
    ├── RCE (Remote Code Execution)
    ├── Unauth config download
    ├── Unauth firmware upload
    └── Disable verification
```

**Sample Vulnerabilities:**
```markdown
D-LINK DIR846 RCE1.MD
D-LINK DIR846 auth change admin pass.MD
D-LINK DIR846 unauth change admin pass.MD
D-LINK DIR846 unauth FirmWare upload.MD
```

#### TP-Link Vulnerabilities
```
TP-Link/
└── [Various models]
```

#### Xiaomi MiWifi Vulnerabilities
```
MiWifi/
└── [Various models]
```

#### JAMF Vulnerabilities
```
JAMF/
└── [JAMF Pro vulnerabilities]
```

**Vulnerability Types:**
- Authentication bypass
- Remote code execution (RCE)
- Unauthorized configuration changes
- Firmware upload vulnerabilities
- Default credential issues

**Relevance to Specter:**
- ❌ Router vulnerabilities not directly applicable to Android spyware
- ℹ️ Useful for network penetration testing
- ℹ️ Could enable lateral movement in network environments
- ℹ️ Shows PAGalaxyLab's IoT security research

---

## Repository Summary Matrix

| Repository | Type | Language | Platform | Relevance to Specter |
|------------|------|----------|----------|---------------------|
| **YAHFA** | Framework | Java/C++ | Android | High (educational) |
| **VxHunter** | Tool | Python | VxWorks | Low (different platform) |
| **Ghidra Scripts** | Tools | Python | Multi | Medium (RE tools) |
| **VulInfo** | Research | Markdown | IoT/Routers | Low (network focus) |

---

## Integration with PREDATOR Research

### YAHFA's Role in PREDATOR

**Direct Connection:**
PREDATOR spyware uses YAHFA framework for application hiding:

```
PREDATOR/ALIEN Architecture
├── ALIEN (Injected into zygote64)
│   ├── Embedded DEX file (com.jnative.pluginshideapp)
│   └── YAHFA initialization code
│
└── YAHFA Hooks
    ├── PackageManager.getInstalledApplications()
    ├── PackageManager.getInstalledPackages()
    └── PackageManager.queryIntentReceiversInternal()
```

**Implementation:**
1. ALIEN loads embedded DEX via InMemoryDexClassLoader
2. DEX contains YAHFA hook definitions
3. Hooks filter hidden packages (read from `/data/system/.0`)
4. Spyware becomes invisible in app lists and doesn't auto-start on boot

**Analysis Documents:**
- [PREDATOR_ANALYSIS.md](PREDATOR_ANALYSIS.md) - Overview
- [PREDATOR_DATA_TARGETS.md](PREDATOR_DATA_TARGETS.md) - Collection targets
- [YAHFA_APP_HIDING_ANALYSIS.md](YAHFA_APP_HIDING_ANALYSIS.md) - Detailed YAHFA analysis
- [PREDATOR_RESEARCH_SUMMARY.md](PREDATOR_RESEARCH_SUMMARY.md) - Master summary

---

## PAGalaxyLab Research Focus

### Primary Areas

1. **Android Security**
   - ART hooking (YAHFA)
   - Malware analysis
   - Application hiding techniques

2. **Embedded Systems**
   - VxWorks firmware analysis (VxHunter)
   - Router security research (VulInfo)
   - Industrial control systems

3. **Reverse Engineering**
   - Ghidra automation scripts
   - OLLVM deobfuscation
   - Function tracing tools

4. **Vulnerability Research**
   - IoT device vulnerabilities
   - Router authentication bypasses
   - Remote code execution

### Notable Achievements

- **YAHFA:** Widely used ART hooking framework (also used by VirtualHook)
- **VulInfo:** Public disclosure of IoT vulnerabilities
- **VxHunter:** Comprehensive VxWorks analysis toolkit
- **PREDATOR Integration:** Their YAHFA framework was adopted by Intellexa's commercial spyware

---

## Research Methodology

### YAHFA Development Process

1. **ART Internals Study**
   - Deep dive into Android Runtime source code
   - ArtMethod structure analysis
   - Entry point redirection techniques

2. **Cross-Version Compatibility**
   - Support Android 7.0 - 12+
   - Handle ArtMethod structure changes
   - Platform-specific adaptations (x86, ARM)

3. **Practical Application**
   - VirtualHook integration (non-root hooking)
   - Used by security researchers
   - Adopted by commercial spyware (PREDATOR)

### VxHunter Development Process

1. **VxWorks Internals**
   - Symbol table format analysis
   - Memory layout understanding
   - Boot loader reverse engineering

2. **Multi-Tool Integration**
   - IDA Pro plugin development
   - Ghidra script support
   - Radare2 compatibility

3. **Real-World Testing**
   - Tested on commercial devices (Schneider, Siemens, TP-Link)
   - CVE research (CVE-2018-19528)
   - Industrial control systems

---

## Ethical and Legal Considerations

### Research Ethics

PAGalaxyLab's repositories serve legitimate purposes:

✅ **Defensive Security:**
- YAHFA helps security researchers understand hooking techniques
- VxHunter enables firmware security audits
- VulInfo provides public vulnerability disclosure

✅ **Education:**
- Open-source frameworks for learning
- Documentation of techniques
- Community contribution

⚠️ **Dual-Use:**
- YAHFA adopted by PREDATOR spyware (malicious use)
- VxHunter could be used to find vulnerabilities for exploitation
- Tools require responsible disclosure and ethical use

### Responsible Use Guidelines

**DO:**
- Use for authorized security testing
- Contribute to defensive security
- Follow responsible disclosure
- Respect licenses and terms

**DO NOT:**
- Deploy YAHFA for unauthorized surveillance
- Use VxHunter findings for malicious exploitation
- Violate device warranties or terms of service
- Target systems without authorization

---

## Related Research

### Other Android Hooking Frameworks

1. **Xposed Framework**
   - Older Android hooking framework
   - Requires root and custom recovery
   - More widely known than YAHFA

2. **Frida**
   - Dynamic instrumentation toolkit
   - JavaScript-based hooking
   - Cross-platform (Android, iOS, Windows, etc.)

3. **Substrate (Cydia Substrate)**
   - Mobile substrate for iOS and Android
   - Commercial license
   - Used by jailbreak tweaks

**YAHFA Advantages:**
- More efficient than Xposed
- Works with VirtualHook (non-root)
- Specifically designed for ART runtime

### Other Firmware Analysis Tools

1. **Binwalk**
   - Firmware extraction and analysis
   - General-purpose (not VxWorks-specific)

2. **Firmwalker**
   - Filesystem analysis
   - Search for credentials and secrets

3. **FirmAE**
   - Automated firmware emulation
   - Dynamic analysis

**VxHunter Advantages:**
- VxWorks-specific optimizations
- Multi-tool support (IDA, Ghidra, R2)
- Serial debugging capabilities

---

## References

### Primary Sources

1. **YAHFA GitHub:** https://github.com/PAGalaxyLab/YAHFA
2. **YAHFA Introduction:** http://rk700.github.io/2017/03/30/YAHFA-introduction/
3. **VxHunter GitHub:** https://github.com/PAGalaxyLab/vxhunter
4. **Ghidra Scripts:** https://github.com/PAGalaxyLab/ghidra_scripts
5. **VulInfo:** https://github.com/PAGalaxyLab/VulInfo

### Related Documentation

6. **Cisco Talos PREDATOR Analysis:** https://blog.talosintelligence.com/predator-spyware/
7. **VirtualHook Project:** https://github.com/rk700/VirtualHook
8. **Android ART Source:** https://source.android.com/docs/core/runtime

---

## Conclusion

PAGalaxyLab maintains a diverse portfolio of security research tools:

**Android Security (YAHFA):**
- Cutting-edge ART hooking framework
- Adopted by both legitimate researchers and commercial spyware
- Demonstrates deep understanding of Android internals

**Embedded Systems (VxHunter):**
- Comprehensive VxWorks analysis toolkit
- Supports multiple reverse engineering platforms
- Real-world testing on industrial devices

**Reverse Engineering (Ghidra Scripts):**
- Productivity tools for malware analysis
- OLLVM deobfuscation
- DEX and Objective-C analysis

**Vulnerability Research (VulInfo):**
- Responsible disclosure of IoT vulnerabilities
- Router and embedded device security
- Public contribution to security awareness

**Impact:**
Their YAHFA framework's adoption by PREDATOR spyware highlights the dual-use nature of security research tools. This underscores the importance of:
- Ethical use guidelines
- Responsible disclosure practices
- Community awareness of defensive vs offensive use

**Value to Security Community:**
- Open-source tools for defensive research
- Educational resources for learning
- Advancement of security analysis capabilities

---

**Index Compiled:** 2026-01-28
**Repositories Analyzed:** 4 (YAHFA, VxHunter, Ghidra Scripts, VulInfo)
**Total Documentation:** 90KB+ across multiple analysis files
**Purpose:** Educational reference for authorized security research
