package com.divine.specter.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp

/**
 * Secret codes, USSD codes, and dialer codes for Android devices.
 * These open hidden diagnostic menus and developer tools.
 */
object SecretCodes {

    enum class Category(val displayName: String, val icon: @Composable () -> Unit) {
        SAMSUNG("Samsung ✓", { Icon(Icons.Default.PhoneAndroid, null) }),
        SMS("SMS Codes", { Icon(Icons.Default.Sms, null) }),
        CARRIER("Carrier", { Icon(Icons.Default.SimCard, null) }),
        DIAGNOSTIC("Diagnostic", { Icon(Icons.Default.BugReport, null) }),
        HARDWARE("Hardware Test", { Icon(Icons.Default.Memory, null) }),
        NETWORK("Network", { Icon(Icons.Default.SignalCellularAlt, null) }),
        INFO("Device Info", { Icon(Icons.Default.Info, null) }),
        DEVELOPER("Developer", { Icon(Icons.Default.Code, null) }),
        DANGEROUS("Dangerous", { Icon(Icons.Default.Warning, null) })
    }

    data class SecretCode(
        val code: String,
        val name: String,
        val description: String,
        val category: Category,
        val brands: List<String> = listOf("all"), // "all", "samsung", "google", "xiaomi", etc.
        val dangerous: Boolean = false,
        val requiresDialer: Boolean = true // Some codes work via intent, others need dialer
    )

    // Universal Android codes
    private val universalCodes = listOf(
        // Diagnostic
        SecretCode(
            "*#*#4636#*#*", "Testing Menu",
            "Phone info, battery stats, usage statistics, WiFi info",
            Category.DIAGNOSTIC
        ),
        SecretCode(
            "*#*#7780#*#*", "Factory Reset",
            "Reset phone to factory state (keeps SD card)",
            Category.DANGEROUS, dangerous = true
        ),
        SecretCode(
            "*#*#7594#*#*", "Power Button Behavior",
            "Change power button to direct power off (skip menu)",
            Category.DEVELOPER
        ),
        SecretCode(
            "*#*#8351#*#*", "Voice Dialer Logging",
            "Enable voice dialer logging",
            Category.DEVELOPER
        ),
        SecretCode(
            "*#*#8350#*#*", "Disable Voice Logging",
            "Disable voice dialer logging",
            Category.DEVELOPER
        ),

        // Hardware Tests
        SecretCode(
            "*#*#0*#*#*", "LCD Test",
            "Display test - shows colors to check for dead pixels",
            Category.HARDWARE
        ),
        SecretCode(
            "*#*#0842#*#*", "Vibration Test",
            "Test vibration motor and backlight",
            Category.HARDWARE
        ),
        SecretCode(
            "*#*#2664#*#*", "Touchscreen Test",
            "Touch screen calibration and test",
            Category.HARDWARE
        ),
        SecretCode(
            "*#*#0588#*#*", "Proximity Sensor",
            "Test proximity sensor",
            Category.HARDWARE
        ),
        SecretCode(
            "*#*#0673#*#*", "Audio Test",
            "Melody test for speakers",
            Category.HARDWARE
        ),
        SecretCode(
            "*#*#0289#*#*", "Audio Test Alt",
            "Alternative audio/melody test",
            Category.HARDWARE
        ),
        SecretCode(
            "*#*#2663#*#*", "Touchscreen Version",
            "Shows touchscreen firmware version",
            Category.HARDWARE
        ),
        SecretCode(
            "*#*#34971539#*#*", "Camera Info",
            "Camera firmware info and updates",
            Category.HARDWARE
        ),

        // Network
        SecretCode(
            "*#*#4636#*#*", "Network Info",
            "Detailed network/cell info (same as testing menu)",
            Category.NETWORK
        ),
        SecretCode(
            "*#*#232338#*#*", "WiFi MAC",
            "Display WiFi MAC address",
            Category.NETWORK
        ),
        SecretCode(
            "*#*#232337#*#*", "Bluetooth MAC",
            "Display Bluetooth MAC address",
            Category.NETWORK
        ),
        SecretCode(
            "*#*#526#*#*", "WLAN Test",
            "Wireless LAN test mode",
            Category.NETWORK
        ),
        SecretCode(
            "*#*#232331#*#*", "Bluetooth Test",
            "Bluetooth test mode",
            Category.NETWORK
        ),
        SecretCode(
            "*#*#232339#*#*", "WiFi Test",
            "WiFi test mode",
            Category.NETWORK
        ),

        // Device Info
        SecretCode(
            "*#06#", "IMEI Number",
            "Display device IMEI (works in dialer)",
            Category.INFO, requiresDialer = true
        ),
        SecretCode(
            "*#*#1234#*#*", "Software Version",
            "PDA and phone firmware version",
            Category.INFO
        ),
        SecretCode(
            "*#*#1111#*#*", "FTA Software",
            "FTA software version",
            Category.INFO
        ),
        SecretCode(
            "*#*#2222#*#*", "FTA Hardware",
            "FTA hardware version",
            Category.INFO
        ),
        SecretCode(
            "*#*#3264#*#*", "RAM Version",
            "Display RAM version info",
            Category.INFO
        ),
        SecretCode(
            "*#*#44336#*#*", "Build Info",
            "PDA, CSC, build time info",
            Category.INFO
        ),

        // Developer
        SecretCode(
            "*#*#8255#*#*", "GTalk Monitor",
            "Google Talk service monitor",
            Category.DEVELOPER
        ),
        SecretCode(
            "*#*#426#*#*", "Google Play Services",
            "Google Play Services debug info",
            Category.DEVELOPER
        ),
        SecretCode(
            "*#*#759#*#*", "RLZ Debug",
            "Google Partner Setup (RLZ) debug",
            Category.DEVELOPER
        ),
        SecretCode(
            "*#*#225#*#*", "Calendar Storage",
            "Calendar storage info",
            Category.DEVELOPER
        )
    )

    // Samsung-specific codes (tested on One UI 6.x / S24 series)
    private val samsungCodes = listOf(
        // === CONFIRMED WORKING ON S24 ULTRA ===
        SecretCode(
            "*#0*#", "Hardware Test Menu ✓",
            "WORKS! Full diagnostic suite - test display colors, touch, sensors, speakers, camera, LED, vibration. Type directly in Phone app.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#1234#", "Software Version ✓",
            "WORKS! Shows AP/CP/CSC firmware versions. Useful for checking if you have latest updates.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#0228#", "Battery Status ✓",
            "WORKS! Detailed battery diagnostics - voltage, temperature, ADC readings, battery health percentage.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#9900#", "SysDump Mode ✓",
            "WORKS! Access system logs, delete dumpstate/logcat, battery history, CP RAM logging. Great for debugging.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#0011#", "Service Mode ✓",
            "WORKS! Shows live network info - cell tower ID, signal strength (dBm), band, connection type (5G/LTE).",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#2663#", "TSP/TSK Firmware ✓",
            "WORKS! Touchscreen and touch key firmware version. Can update touchscreen firmware.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#0808#", "USB Settings ✓",
            "WORKS! Change USB mode - MTP, PTP, RNDIS, DM+MODEM+ADB. Useful for development.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#12580*369#", "Software/Hardware Info ✓",
            "WORKS! Shows detailed device info - HW version, build date, Bluetooth/WiFi addresses.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#34971539#", "Camera Firmware ✓",
            "WORKS! Camera module info and firmware. Shows front/rear camera details.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),

        // === MAY WORK (DEPENDS ON CARRIER/REGION) ===
        SecretCode(
            "*#7353#", "Quick Test Menu",
            "May work - Quick access to common hardware tests (speaker, vibration, touch, camera).",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#0283#", "Audio Loopback",
            "May work - Tests microphone by playing back what it hears through speaker.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#0673#", "Audio Test",
            "May work - Speaker/audio melody test.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#0782#", "RTC Test",
            "May work - Real-time clock accuracy test.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#0589#", "Light Sensor",
            "May work - Ambient light sensor test.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#0588#", "Proximity Sensor",
            "May work - Proximity sensor test (cover the sensor).",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#9090#", "Diagnostic Config",
            "May work - UART/USB diagnostic logging configuration.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#2222#", "Hardware Version",
            "May work - Hardware version and board info.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#44336#", "Build Info",
            "May work - Build time and CSC info.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),

        // === ADVANCED/DANGEROUS ===
        SecretCode(
            "*#197328640#", "Service Mode",
            "Engineering service mode - advanced network settings. May not work on retail devices.",
            Category.SAMSUNG, brands = listOf("samsung")
        ),
        SecretCode(
            "*#272*IMEI#", "CSC Change",
            "⚠️ Change region code (CSC). Can affect features/apps. Replace IMEI with your actual IMEI.",
            Category.SAMSUNG, brands = listOf("samsung"), dangerous = true
        ),
        SecretCode(
            "*#7412365#", "Camera Firmware Menu",
            "Camera firmware update - don't use unless you know what you're doing.",
            Category.SAMSUNG, brands = listOf("samsung"), dangerous = true
        )
    )

    // Carrier-specific codes (US carriers)
    private val carrierCodes = listOf(
        // T-Mobile / Metro
        SecretCode(
            "#932#", "T-Mobile Device Unlock",
            "Check T-Mobile device unlock status. Only works on T-Mobile network.",
            Category.CARRIER, brands = listOf("all")
        ),
        SecretCode(
            "#763#", "T-Mobile VoLTE",
            "Check VoLTE (Voice over LTE) status on T-Mobile.",
            Category.CARRIER, brands = listOf("all")
        ),
        SecretCode(
            "*#0011#", "Network Signal Info",
            "Detailed signal strength and cell tower info. Works on most carriers.",
            Category.CARRIER, brands = listOf("samsung")
        ),
        SecretCode(
            "##786#", "RTN Reset (Sprint/TMo)",
            "View reset counter and device info. Sprint/T-Mobile devices.",
            Category.CARRIER, brands = listOf("all")
        ),
        SecretCode(
            "##3282#", "Data Usage (Sprint)",
            "Check data usage on Sprint/T-Mobile legacy.",
            Category.CARRIER, brands = listOf("all")
        ),

        // AT&T
        SecretCode(
            "*#*#4636#*#*", "Phone Info (AT&T)",
            "May work on AT&T - shows phone/battery stats.",
            Category.CARRIER, brands = listOf("all")
        ),

        // Verizon
        SecretCode(
            "*#*#4636#*#*", "Phone Info (Verizon)",
            "May work on Verizon - shows device information.",
            Category.CARRIER, brands = listOf("all")
        ),
        SecretCode(
            "*228", "Verizon Activation",
            "Verizon OTA activation (legacy CDMA). Not needed on newer devices.",
            Category.CARRIER, brands = listOf("all")
        ),

        // Universal
        SecretCode(
            "*#06#", "IMEI Display",
            "Shows IMEI number. Works on ALL phones and carriers.",
            Category.INFO, brands = listOf("all")
        ),
        SecretCode(
            "*646#", "Minutes Balance",
            "Check remaining minutes (carrier dependent).",
            Category.CARRIER, brands = listOf("all")
        ),
        SecretCode(
            "*225#", "Bill Balance",
            "Check bill balance (carrier dependent).",
            Category.CARRIER, brands = listOf("all")
        ),
        SecretCode(
            "*3282#", "Data Balance",
            "Check data usage balance (carrier dependent).",
            Category.CARRIER, brands = listOf("all")
        )
    )

    // Google Pixel codes
    private val pixelCodes = listOf(
        SecretCode(
            "*#*#7287#*#*", "Google Testing",
            "Google/Pixel specific testing menu",
            Category.DIAGNOSTIC, brands = listOf("google")
        ),
        SecretCode(
            "*#*#4636#*#*", "Phone Info (Pixel)",
            "Testing menu works well on Pixel devices - phone info, battery, WiFi, usage stats.",
            Category.DIAGNOSTIC, brands = listOf("google")
        )
    )

    // SMS Shortcodes (text these keywords to the number)
    private val smsCodes = listOf(
        // T-Mobile
        SecretCode(
            "BAL → 611", "T-Mobile Balance",
            "Text 'BAL' to 611 to check your account balance.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "DATA → 611", "T-Mobile Data Usage",
            "Text 'DATA' to 611 to see how much data you've used this cycle.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "MIN → 611", "T-Mobile Minutes",
            "Text 'MIN' to 611 to check remaining minutes (if applicable).",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "UPGRADE → 611", "T-Mobile Upgrade",
            "Text 'UPGRADE' to 611 to check phone upgrade eligibility.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "APN → 611", "T-Mobile APN Settings",
            "Text 'APN' to 611 to receive automatic network configuration.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),

        // AT&T
        SecretCode(
            "DATA → 3282", "AT&T Data Usage",
            "Text 'DATA' to 3282 (DATA) to check data usage on AT&T.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "BAL → 3282", "AT&T Balance",
            "Text 'BAL' to 3282 to check account balance on AT&T.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "USAGE → 3282", "AT&T Usage Summary",
            "Text 'USAGE' to 3282 for complete usage summary on AT&T.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),

        // Verizon
        SecretCode(
            "#DATA → 3282", "Verizon Data Usage",
            "Text '#DATA' to 3282 to check data usage on Verizon.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "#BAL → 3282", "Verizon Balance",
            "Text '#BAL' to 3282 to check balance on Verizon.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "#MIN → 3282", "Verizon Minutes",
            "Text '#MIN' to 3282 to check minutes used on Verizon.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),

        // Universal
        SecretCode(
            "STOP → [any]", "Unsubscribe from SMS",
            "Text 'STOP' to any shortcode to unsubscribe from their messages. Works universally.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "HELP → [any]", "Get SMS Help",
            "Text 'HELP' to any shortcode to get info about that service.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),

        // Emergency & Crisis
        SecretCode(
            "[msg] → 911", "Text 911 Emergency",
            "Text-to-911 is available in most US areas. Use when you can't speak. Include location.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "[msg] → 741741", "Crisis Text Line",
            "Free 24/7 mental health support. Text HOME or any message to connect with a counselor.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "[msg] → 233733", "Human Trafficking Help",
            "BEFREE hotline. Text for help or to report suspected trafficking.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        ),
        SecretCode(
            "[msg] → 839863", "Suicide Prevention",
            "Text STEVE to 839863 for Veterans Crisis Line support.",
            Category.SMS, brands = listOf("all"), requiresDialer = false
        )
    )

    val all: List<SecretCode> = samsungCodes + smsCodes + carrierCodes + universalCodes + pixelCodes

    fun getByCategory(category: Category): List<SecretCode> {
        return all.filter { it.category == category }
    }

    fun getForDevice(context: Context): List<SecretCode> {
        val manufacturer = Build.MANUFACTURER.lowercase()
        return all.filter { code ->
            code.brands.contains("all") || code.brands.any { manufacturer.contains(it) }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CodesScreen() {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current

    var selectedCategory by remember { mutableStateOf<SecretCodes.Category?>(null) }
    var showAllCodes by remember { mutableStateOf(false) }
    var snackbarMessage by remember { mutableStateOf<String?>(null) }

    val snackbarHostState = remember { SnackbarHostState() }

    // Show snackbar when message changes
    LaunchedEffect(snackbarMessage) {
        snackbarMessage?.let {
            snackbarHostState.showSnackbar(it, duration = SnackbarDuration.Short)
            snackbarMessage = null
        }
    }

    // Filter codes
    val allCodes = if (showAllCodes) SecretCodes.all else SecretCodes.getForDevice(context)
    val codes = if (selectedCategory != null) {
        allCodes.filter { it.category == selectedCategory }
    } else {
        allCodes
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(SpecterColors.Background)
                .padding(padding)
        ) {
            // Info card
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                colors = CardDefaults.cardColors(containerColor = SpecterColors.Surface)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.Dialpad,
                        contentDescription = null,
                        tint = SpecterColors.Primary
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Secret Dialer Codes",
                            style = MaterialTheme.typography.titleSmall,
                            color = SpecterColors.OnSurface
                        )
                        Text(
                            text = "Tap to copy, long-press to dial directly",
                            style = MaterialTheme.typography.bodySmall,
                            color = SpecterColors.OnSurface.copy(alpha = 0.6f)
                        )
                    }
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = "Show All",
                            style = MaterialTheme.typography.bodySmall,
                            color = SpecterColors.OnSurface.copy(alpha = 0.7f)
                        )
                        Switch(
                            checked = showAllCodes,
                            onCheckedChange = { showAllCodes = it },
                            modifier = Modifier.height(24.dp),
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = SpecterColors.Primary,
                                checkedTrackColor = SpecterColors.Primary.copy(alpha = 0.5f)
                            )
                        )
                    }
                }
            }

            // Category filter chips
            LazyRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                item {
                    FilterChip(
                        selected = selectedCategory == null,
                        onClick = { selectedCategory = null },
                        label = { Text("All (${allCodes.size})") }
                    )
                }

                items(SecretCodes.Category.entries.toList()) { category ->
                    val count = allCodes.count { it.category == category }
                    if (count > 0) {
                        FilterChip(
                            selected = selectedCategory == category,
                            onClick = { selectedCategory = category },
                            label = { Text("${category.displayName} ($count)") },
                            leadingIcon = if (selectedCategory == category) {
                                { category.icon() }
                            } else null
                        )
                    }
                }
            }

            // Codes list
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(codes) { code ->
                    SecretCodeCard(
                        code = code,
                        onCopy = {
                            clipboardManager.setText(AnnotatedString(code.code))
                            snackbarMessage = "Copied: ${code.code}"
                        },
                        onDial = {
                            try {
                                // Try to dial the code
                                val intent = Intent(Intent.ACTION_DIAL).apply {
                                    data = Uri.fromParts("tel", code.code, null)
                                }
                                context.startActivity(intent)
                            } catch (e: Exception) {
                                snackbarMessage = "Could not open dialer"
                            }
                        }
                    )
                }

                if (codes.isEmpty()) {
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(32.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "No codes for this category",
                                color = SpecterColors.OnSurface.copy(alpha = 0.5f)
                            )
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecretCodeCard(
    code: SecretCodes.SecretCode,
    onCopy: () -> Unit,
    onDial: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCopy() },
        colors = CardDefaults.cardColors(
            containerColor = if (code.dangerous)
                SpecterColors.Error.copy(alpha = 0.1f)
            else
                SpecterColors.Surface
        ),
        onClick = onCopy
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Code in monospace
                    Surface(
                        color = SpecterColors.Primary.copy(alpha = 0.15f),
                        shape = MaterialTheme.shapes.small
                    ) {
                        Text(
                            text = code.code,
                            style = MaterialTheme.typography.titleMedium,
                            fontFamily = FontFamily.Monospace,
                            color = SpecterColors.Primary,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                        )
                    }

                    if (code.dangerous) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Icon(
                            imageVector = Icons.Default.Warning,
                            contentDescription = "Dangerous",
                            tint = SpecterColors.Error,
                            modifier = Modifier.size(18.dp)
                        )
                    }

                    if (code.brands.size == 1 && code.brands[0] != "all") {
                        Spacer(modifier = Modifier.width(8.dp))
                        Surface(
                            color = SpecterColors.SurfaceVariant,
                            shape = MaterialTheme.shapes.extraSmall
                        ) {
                            Text(
                                text = code.brands[0].uppercase(),
                                style = MaterialTheme.typography.labelSmall,
                                color = SpecterColors.OnSurface.copy(alpha = 0.7f),
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                    }
                }

                // Dial button
                IconButton(onClick = onDial) {
                    Icon(
                        imageVector = Icons.Default.Phone,
                        contentDescription = "Dial",
                        tint = SpecterColors.Primary
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = code.name,
                style = MaterialTheme.typography.bodyMedium,
                color = SpecterColors.OnSurface
            )

            Text(
                text = code.description,
                style = MaterialTheme.typography.bodySmall,
                color = SpecterColors.OnSurface.copy(alpha = 0.6f)
            )
        }
    }
}
