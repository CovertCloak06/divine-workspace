package com.divine.specter.scripts

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/**
 * Built-in maintenance scripts.
 * Each script is a collection of shell commands with metadata.
 */
object BuiltinScripts {

    enum class DeviceType {
        PHONE,
        TABLET,
        FIRE_TV,
        ANDROID_TV,
        ALL
    }

    enum class Category {
        CACHE,
        MEMORY,
        BLOATWARE,
        MAINTENANCE,
        DIAGNOSTICS,
        PRIVACY,
        PERFORMANCE,
        APPS,
        NETWORK,
        DEVELOPER,
        SECURITY,
        DISPLAY,
        AUDIO,
        QUICK_ACTIONS
    }

    data class Script(
        val id: String,
        val name: String,
        val description: String,
        val category: Category,
        val commands: List<String>,
        val deviceTypes: Set<DeviceType> = setOf(DeviceType.ALL),
        val requiresRoot: Boolean = false,
        val dangerous: Boolean = false
    )

    /**
     * Detects the current device type.
     */
    fun detectDeviceType(context: Context): DeviceType {
        val pm = context.packageManager

        // Check for Fire TV / Fire OS
        if (Build.MANUFACTURER.equals("Amazon", ignoreCase = true)) {
            val hasLeanback = pm.hasSystemFeature(PackageManager.FEATURE_LEANBACK)
            return if (hasLeanback) DeviceType.FIRE_TV else DeviceType.TABLET
        }

        // Check for Android TV
        if (pm.hasSystemFeature(PackageManager.FEATURE_LEANBACK)) {
            return DeviceType.ANDROID_TV
        }

        // Check for tablet (simple heuristic based on screen size)
        val config = context.resources.configuration
        val screenLayout = config.screenLayout and android.content.res.Configuration.SCREENLAYOUT_SIZE_MASK
        if (screenLayout >= android.content.res.Configuration.SCREENLAYOUT_SIZE_LARGE) {
            return DeviceType.TABLET
        }

        return DeviceType.PHONE
    }

    /**
     * Gets scripts applicable to a specific device type.
     */
    fun getForDevice(deviceType: DeviceType): List<Script> {
        return all.filter { script ->
            script.deviceTypes.contains(DeviceType.ALL) || script.deviceTypes.contains(deviceType)
        }
    }

    val all: List<Script> = listOf(
        // ═══════════════════════════════════════════════════════════════
        // CACHE CLEARING
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "clear_system_cache",
            name = "Clear System Cache",
            description = "Removes system diagnostic files: crash reports (dropbox), ANR traces, and tombstones from failed processes. Safe to run regularly. Frees storage and can help if your device feels sluggish after app crashes.",
            category = Category.CACHE,
            commands = listOf(
                "rm -rf /data/system/dropbox/* 2>/dev/null || true",
                "rm -rf /data/anr/* 2>/dev/null || true",
                "rm -rf /data/tombstones/* 2>/dev/null || true",
                "echo 'System cache cleared'"
            )
        ),
        Script(
            id = "clear_app_cache",
            name = "Clear All App Caches",
            description = "Wipes cached data for every user-installed app. Frees storage without deleting app data, logins, or settings. Apps may load slower the first time after clearing as they rebuild their cache. Safe and effective for reclaiming space.",
            category = Category.CACHE,
            commands = listOf(
                "pm list packages -3 | cut -d: -f2 | while read pkg; do pm clear --cache-only \$pkg 2>/dev/null; done",
                "echo 'App caches cleared'"
            )
        ),
        Script(
            id = "clear_temp_files",
            name = "Clear Temp Files",
            description = "Deletes temporary files from /data/local/tmp and app cache directories on SD card. These accumulate from app updates, failed downloads, and background processes. Safe cleanup that won't affect app functionality.",
            category = Category.CACHE,
            commands = listOf(
                "rm -rf /data/local/tmp/* 2>/dev/null || true",
                "rm -rf /sdcard/Android/data/*/cache/* 2>/dev/null || true",
                "echo 'Temp files cleared'"
            )
        ),
        Script(
            id = "clear_dalvik_cache",
            name = "Clear Dalvik/ART Cache",
            description = "⚠️ Removes compiled app bytecode from the Dalvik/ART runtime. After clearing, every app will need to recompile on first launch, causing temporary slowness. Use only if apps are behaving strangely. Reboot recommended after.",
            category = Category.CACHE,
            commands = listOf(
                "rm -rf /data/dalvik-cache/* 2>/dev/null || true",
                "echo 'Dalvik cache cleared - reboot recommended'"
            ),
            dangerous = true
        ),

        // ═══════════════════════════════════════════════════════════════
        // MEMORY OPTIMIZATION
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "kill_background_apps",
            name = "Kill Background Apps",
            description = "Immediately terminates all apps running in the background. Frees RAM for demanding apps or games. Apps will need to reload when reopened. Won't affect foreground apps or the current screen.",
            category = Category.MEMORY,
            commands = listOf(
                "am kill-all",
                "echo 'Background apps killed'"
            )
        ),
        Script(
            id = "trim_memory",
            name = "Request Memory Trim",
            description = "Politely asks all running apps to release cached memory they're not actively using. Gentler than killing apps - they remain running but shed excess RAM. Good for a quick memory cleanup without disruption.",
            category = Category.MEMORY,
            commands = listOf(
                "am send-trim-memory --user 0 -a -l RUNNING_CRITICAL 2>/dev/null || am kill-all",
                "echo 'Memory trim requested'"
            )
        ),
        Script(
            id = "aggressive_memory_free",
            name = "Aggressive Memory Free",
            description = "🔥 MAXIMUM RAM RECOVERY: Combines memory trim, process killing, and filesystem sync for maximum RAM recovery. Use before launching heavy games or when your device is severely low on memory. Apps will reload when accessed.",
            category = Category.MEMORY,
            commands = listOf(
                "am send-trim-memory --user 0 -a -l RUNNING_CRITICAL 2>/dev/null || true",
                "am kill-all",
                "sync",
                "echo 'Aggressive memory free complete'"
            )
        ),
        Script(
            id = "drop_caches",
            name = "Drop Filesystem Caches",
            description = "Forces the kernel to release page cache, dentries, and inodes from RAM. Only works with root access. Useful for testing or extreme memory situations. The system will rebuild these caches as needed.",
            category = Category.MEMORY,
            commands = listOf(
                "sync",
                "echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || echo 'Requires root'",
                "echo 'Filesystem caches dropped'"
            ),
            requiresRoot = true
        ),

        // ═══════════════════════════════════════════════════════════════
        // PERFORMANCE
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "boost_performance",
            name = "Performance Boost",
            description = "🚀 Quick optimization combo: kills background apps, clears system diagnostic files, and requests memory trim from all apps. Run before gaming or resource-intensive tasks for a noticeable responsiveness improvement.",
            category = Category.PERFORMANCE,
            commands = listOf(
                "am kill-all",
                "rm -rf /data/system/dropbox/* 2>/dev/null || true",
                "am send-trim-memory --user 0 -a -l RUNNING_CRITICAL 2>/dev/null || true",
                "echo 'Performance boost complete'"
            )
        ),
        Script(
            id = "stop_heavy_apps",
            name = "Stop Heavy Apps",
            description = "Force-stops notorious RAM hogs: Facebook, Instagram, Snapchat, TikTok, YouTube, Netflix, Spotify, and Twitter. These apps often run background services even when 'closed'. Stops them completely until you manually reopen.",
            category = Category.PERFORMANCE,
            commands = listOf(
                "am force-stop com.facebook.katana 2>/dev/null || true",
                "am force-stop com.facebook.orca 2>/dev/null || true",
                "am force-stop com.instagram.android 2>/dev/null || true",
                "am force-stop com.snapchat.android 2>/dev/null || true",
                "am force-stop com.google.android.youtube 2>/dev/null || true",
                "am force-stop com.netflix.mediaclient 2>/dev/null || true",
                "am force-stop com.spotify.music 2>/dev/null || true",
                "am force-stop com.twitter.android 2>/dev/null || true",
                "am force-stop com.zhiliaoapp.musically 2>/dev/null || true",
                "echo 'Heavy apps stopped'"
            )
        ),
        Script(
            id = "disable_animations",
            name = "Disable Animations",
            description = "Removes all transition animations, window animations, and UI effects. Makes the phone feel faster and more responsive instantly. Great for older devices or anyone who prefers speed over eye candy.",
            category = Category.PERFORMANCE,
            commands = listOf(
                "settings put global window_animation_scale 0",
                "settings put global transition_animation_scale 0",
                "settings put global animator_duration_scale 0",
                "echo 'Animations disabled'"
            )
        ),
        Script(
            id = "enable_animations",
            name = "Enable Animations",
            description = "Restores smooth window transitions and UI animations to default values. Use to bring back the polished look after testing with animations disabled. System default is 1x animation speed.",
            category = Category.PERFORMANCE,
            commands = listOf(
                "settings put global window_animation_scale 1",
                "settings put global transition_animation_scale 1",
                "settings put global animator_duration_scale 1",
                "echo 'Animations enabled'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // BLOATWARE - SAMSUNG
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "stop_samsung_bloat",
            name = "Stop Samsung Services",
            description = "Force-stops Samsung's background services: Bixby assistant, Game Launcher, Tips app, Samsung Cloud, and Galaxy Store. Frees RAM and battery without permanently disabling features. Services restart after reboot.",
            category = Category.BLOATWARE,
            deviceTypes = setOf(DeviceType.PHONE, DeviceType.TABLET),
            commands = listOf(
                "am force-stop com.samsung.android.bixby.agent 2>/dev/null || true",
                "am force-stop com.samsung.android.bixby.service 2>/dev/null || true",
                "am force-stop com.samsung.android.visionintelligence 2>/dev/null || true",
                "am force-stop com.samsung.android.game.gamehome 2>/dev/null || true",
                "am force-stop com.samsung.android.game.gametools 2>/dev/null || true",
                "am force-stop com.samsung.android.app.tips 2>/dev/null || true",
                "am force-stop com.samsung.android.mobileservice 2>/dev/null || true",
                "am force-stop com.samsung.android.app.spage 2>/dev/null || true",
                "echo 'Samsung bloatware stopped'"
            )
        ),
        Script(
            id = "disable_bixby",
            name = "Disable Bixby",
            description = "Permanently disables Bixby Voice, Bixby Vision, and the Bixby service. The side button will no longer trigger Bixby. Frees significant background resources. Can be re-enabled anytime.",
            category = Category.BLOATWARE,
            deviceTypes = setOf(DeviceType.PHONE, DeviceType.TABLET),
            commands = listOf(
                "pm disable-user --user 0 com.samsung.android.bixby.agent 2>/dev/null || true",
                "pm disable-user --user 0 com.samsung.android.bixby.service 2>/dev/null || true",
                "pm disable-user --user 0 com.samsung.android.visionintelligence 2>/dev/null || true",
                "pm disable-user --user 0 com.samsung.android.bixby.wakeup 2>/dev/null || true",
                "echo 'Bixby disabled'"
            )
        ),
        Script(
            id = "reenable_bixby",
            name = "Re-enable Bixby",
            description = "Restores all Bixby services after they were disabled. Brings back Bixby Voice assistant, Vision camera features, and the side button trigger. May require a reboot to fully activate.",
            category = Category.BLOATWARE,
            deviceTypes = setOf(DeviceType.PHONE, DeviceType.TABLET),
            commands = listOf(
                "pm enable com.samsung.android.bixby.agent 2>/dev/null || true",
                "pm enable com.samsung.android.bixby.service 2>/dev/null || true",
                "pm enable com.samsung.android.visionintelligence 2>/dev/null || true",
                "echo 'Bixby re-enabled'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // BLOATWARE - FIRE TV
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "disable_fire_ads",
            name = "Disable Fire TV Ads",
            description = "Removes sponsored content and banner ads from Fire TV home screen. Disables Amazon's advertising service, game store promotions, and personalized ad targeting. Your home screen will be cleaner with fewer distractions.",
            category = Category.BLOATWARE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm disable-user --user 0 com.amazon.device.software.ota 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.ags.app 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.vizzini 2>/dev/null || true",
                "settings put global show_first_crash_dialog_dev_option 0 2>/dev/null || true",
                "echo 'Fire TV ads disabled'"
            )
        ),
        Script(
            id = "stop_fire_services",
            name = "Stop Amazon Services",
            description = "Temporarily stops Amazon background services that consume RAM and CPU. Includes OTA updater, game store, Kindle, Prime Video, and home recommendations. Services will restart after reboot - use 'Disable' scripts for permanent effect.",
            category = Category.BLOATWARE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am force-stop com.amazon.device.software.ota",
                "am force-stop com.amazon.ags.app",
                "am force-stop com.amazon.kindle",
                "am force-stop com.amazon.avod",
                "am force-stop com.amazon.firehomerecommendations",
                "echo 'Amazon services stopped'"
            )
        ),
        Script(
            id = "fire_kill_telemetry",
            name = "Kill Fire TV Telemetry",
            description = "Stops Amazon from collecting usage data, crash reports, and device metrics. Disables ODS (On-Device Software) monitoring, metrics service, log manager, and crash reporter. Improves privacy and reduces background network activity.",
            category = Category.BLOATWARE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm disable-user --user 0 com.amazon.device.software.ods 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.metrics.service 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.device.logmanager 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.kindle.devicecontrols 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.device.crashmanager 2>/dev/null || true",
                "settings put secure send_action_app_error 0 2>/dev/null || true",
                "echo 'Fire TV telemetry disabled'"
            )
        ),
        Script(
            id = "fire_disable_screensaver_ads",
            name = "Disable Screensaver Ads",
            description = "Removes the promotional screensaver that shows Amazon product ads when your Fire TV is idle. Disables both the photo slideshow with ads and the default screensaver. Your TV will display a blank screen instead.",
            category = Category.BLOATWARE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm disable-user --user 0 com.amazon.bueller.photos 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.ftv.screensaver 2>/dev/null || true",
                "settings put secure screensaver_components '' 2>/dev/null || true",
                "settings put secure screensaver_enabled 0 2>/dev/null || true",
                "echo 'Screensaver ads disabled'"
            )
        ),
        Script(
            id = "fire_disable_alexa",
            name = "Disable Alexa",
            description = "Completely disables Alexa voice assistant on your Fire TV. Stops the microphone from listening for wake words, removes voice search capability, and prevents Alexa-related background processes. The mic button will no longer trigger voice commands.",
            category = Category.BLOATWARE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm disable-user --user 0 com.amazon.avs.sample 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.alexa.externalmediaplayer.fireos 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.vizzini 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.tv.alexa 2>/dev/null || true",
                "am force-stop com.amazon.vizzini 2>/dev/null || true",
                "echo 'Alexa disabled'"
            )
        ),
        Script(
            id = "fire_disable_recommendations",
            name = "Disable Recommendations",
            description = "Stops Amazon's content recommendation engine that tracks your viewing habits. Removes 'Recommended for You' rows from home screen, disables Glowplug analytics, and turns off Hedwig notification service. Cleaner interface with less tracking.",
            category = Category.BLOATWARE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm disable-user --user 0 com.amazon.firehomerecommendations 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.ftv.glowplug 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.hedwig 2>/dev/null || true",
                "settings put global device_name_recommendation_enabled 0 2>/dev/null || true",
                "echo 'Recommendations disabled'"
            )
        ),
        Script(
            id = "fire_disable_all_amazon",
            name = "Nuclear Debloat",
            description = "⚠️ AGGRESSIVE: Disables ALL non-essential Amazon apps including Prime Video, Kindle, Photos, Music, and all telemetry. Only use if you exclusively use third-party apps (Netflix, Plex, Kodi). Some Fire TV features may break. Use 'Restore Amazon Apps' to undo.",
            category = Category.BLOATWARE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            dangerous = true,
            commands = listOf(
                "pm disable-user --user 0 com.amazon.device.software.ods 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.device.software.ota 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.metrics.service 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.device.logmanager 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.device.crashmanager 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.bueller.photos 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.ftv.screensaver 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.vizzini 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.tv.alexa 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.firehomerecommendations 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.kindle 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.photos 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.music.tv 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.amazonvideo 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.hedwig 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.ftv.glowplug 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.whisperplay.service 2>/dev/null || true",
                "echo 'Nuclear debloat complete - reboot recommended'"
            )
        ),
        Script(
            id = "fire_restore_amazon",
            name = "Restore Amazon Apps",
            description = "Reverses all debloat changes and re-enables every Amazon service. Use this if you ran Nuclear Debloat and want to restore full Fire TV functionality including Prime Video, Alexa, recommendations, and system updates.",
            category = Category.BLOATWARE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm enable com.amazon.device.software.ods 2>/dev/null || true",
                "pm enable com.amazon.device.software.ota 2>/dev/null || true",
                "pm enable com.amazon.metrics.service 2>/dev/null || true",
                "pm enable com.amazon.device.logmanager 2>/dev/null || true",
                "pm enable com.amazon.device.crashmanager 2>/dev/null || true",
                "pm enable com.amazon.bueller.photos 2>/dev/null || true",
                "pm enable com.amazon.ftv.screensaver 2>/dev/null || true",
                "pm enable com.amazon.vizzini 2>/dev/null || true",
                "pm enable com.amazon.tv.alexa 2>/dev/null || true",
                "pm enable com.amazon.firehomerecommendations 2>/dev/null || true",
                "pm enable com.amazon.kindle 2>/dev/null || true",
                "pm enable com.amazon.photos 2>/dev/null || true",
                "pm enable com.amazon.music.tv 2>/dev/null || true",
                "pm enable com.amazon.amazonvideo 2>/dev/null || true",
                "pm enable com.amazon.hedwig 2>/dev/null || true",
                "pm enable com.amazon.ftv.glowplug 2>/dev/null || true",
                "pm enable com.amazon.whisperplay.service 2>/dev/null || true",
                "echo 'Amazon apps restored'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // BLOATWARE - GENERAL
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "disable_telemetry_general",
            name = "Disable Telemetry",
            description = "Stops Android from sending crash reports, app usage data, and error diagnostics to Google/OEM servers. Improves privacy and slightly reduces background network activity. Safe to disable.",
            category = Category.BLOATWARE,
            commands = listOf(
                "settings put global send_action_app_error 0 2>/dev/null || true",
                "settings put secure send_action_app_error 0 2>/dev/null || true",
                "settings put global upload_apk_enable 0 2>/dev/null || true",
                "echo 'Telemetry disabled'"
            )
        ),
        Script(
            id = "stop_google_bloat",
            name = "Stop Google Services",
            description = "Force-stops non-essential Google apps: Digital Wellbeing, Google Assistant, News, Play Movies, Play Music, and Duo. Core services (Play Store, Play Services) remain untouched. Frees RAM from rarely used Google apps.",
            category = Category.BLOATWARE,
            commands = listOf(
                "am force-stop com.google.android.apps.wellbeing 2>/dev/null || true",
                "am force-stop com.google.android.apps.googleassistant 2>/dev/null || true",
                "am force-stop com.google.android.apps.magazines 2>/dev/null || true",
                "am force-stop com.google.android.videos 2>/dev/null || true",
                "am force-stop com.google.android.music 2>/dev/null || true",
                "am force-stop com.google.android.apps.tachyon 2>/dev/null || true",
                "echo 'Google bloatware stopped'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // PRIVACY
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "clear_clipboard",
            name = "Clear Clipboard",
            description = "Wipes any text or data currently copied to the clipboard. Important after copying passwords, credit card numbers, or sensitive information. Prevents accidental pastes and clipboard-sniffing apps.",
            category = Category.PRIVACY,
            commands = listOf(
                "am broadcast -a clipper.set -e text '' 2>/dev/null || service call clipboard 1 2>/dev/null || true",
                "echo 'Clipboard cleared'"
            )
        ),
        Script(
            id = "clear_recent_apps",
            name = "Clear Recent Apps",
            description = "Removes all apps from the Recent Apps / Overview screen. Useful before handing your phone to someone or when you want to hide which apps you've been using. Apps remain installed, just hidden from recents.",
            category = Category.PRIVACY,
            commands = listOf(
                "am broadcast -a com.android.systemui.recent.action.DISMISS_ALL 2>/dev/null || true",
                "echo 'Recent apps cleared'"
            )
        ),
        Script(
            id = "disable_usage_stats",
            name = "Disable Usage Stats",
            description = "Stops Android from tracking which apps you use and for how long. Prevents Digital Wellbeing and third-party apps from seeing your usage patterns. May break some app time-limit features.",
            category = Category.PRIVACY,
            commands = listOf(
                "appops set android USAGE_STATS_HISTORY_CONTROL ignore 2>/dev/null || true",
                "settings put secure usage_stats_user_enabled 0 2>/dev/null || true",
                "echo 'Usage stats disabled'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // APP MANAGEMENT
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "list_user_apps",
            name = "List User Apps",
            description = "Shows all apps you've installed (not system/preinstalled apps). Outputs package names sorted alphabetically. Useful for backup lists, checking what's installed, or finding package names for other scripts.",
            category = Category.APPS,
            commands = listOf(
                "pm list packages -3 | cut -d: -f2 | sort"
            )
        ),
        Script(
            id = "list_disabled_apps",
            name = "List Disabled Apps",
            description = "Shows apps you've disabled (bloatware, unused system apps). These apps are still installed but not running. Use to review what you've disabled or find apps to re-enable.",
            category = Category.APPS,
            commands = listOf(
                "pm list packages -d | cut -d: -f2 | sort"
            )
        ),
        Script(
            id = "list_running_apps",
            name = "List Running Apps",
            description = "Shows apps currently active in memory: the foreground app plus recent background processes. Useful for seeing what's consuming resources or which apps are running when you didn't expect them to.",
            category = Category.APPS,
            commands = listOf(
                "dumpsys activity activities | grep 'mResumedActivity' | head -5",
                "echo '---'",
                "dumpsys activity processes | grep 'ProcessRecord' | head -20"
            )
        ),
        Script(
            id = "grant_all_permissions",
            name = "Show Permission-Heavy Apps",
            description = "Ranks your installed apps by how many permissions they've been granted. Apps with excessive permissions (camera, mic, location, contacts) appear at the top. Useful for privacy audits and finding suspicious apps.",
            category = Category.APPS,
            commands = listOf(
                "for pkg in \$(pm list packages -3 | cut -d: -f2); do count=\$(dumpsys package \$pkg | grep 'granted=true' | wc -l); echo \"\$count \$pkg\"; done | sort -rn | head -10"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // NETWORK
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "network_info",
            name = "Network Information",
            description = "Displays your current WiFi IP address, mobile data IP, and default gateway. Shows connection state and basic network configuration. First step in troubleshooting connectivity issues.",
            category = Category.NETWORK,
            commands = listOf(
                "echo '=== WiFi ==='",
                "ip addr show wlan0 2>/dev/null | grep -E 'inet |state' || echo 'No WiFi'",
                "echo ''",
                "echo '=== Mobile ==='",
                "ip addr show rmnet_data0 2>/dev/null | grep inet || echo 'No mobile data'",
                "echo ''",
                "echo '=== Gateway ==='",
                "ip route | grep default | head -1"
            )
        ),
        Script(
            id = "dns_info",
            name = "DNS Information",
            description = "Shows which DNS servers your phone is using to resolve website addresses. Displays both WiFi and mobile data DNS servers. Useful for verifying custom DNS settings or troubleshooting domain resolution issues.",
            category = Category.NETWORK,
            commands = listOf(
                "getprop net.dns1",
                "getprop net.dns2",
                "getprop net.rmnet_data0.dns1 2>/dev/null || true",
                "getprop net.rmnet_data0.dns2 2>/dev/null || true"
            )
        ),
        Script(
            id = "flush_dns",
            name = "Flush DNS Cache",
            description = "Clears cached DNS lookups forcing fresh resolution of website addresses. Fixes issues where a website recently changed servers but your phone still connects to the old address. Try this when a site works on other devices but not your phone.",
            category = Category.NETWORK,
            commands = listOf(
                "ndc resolver flushdefaultif 2>/dev/null || true",
                "ndc resolver flushif wlan0 2>/dev/null || true",
                "echo 'DNS cache flushed'"
            )
        ),
        Script(
            id = "restart_wifi",
            name = "Restart WiFi",
            description = "Turns WiFi off then back on after 2 seconds. Forces a fresh connection to your router and can fix stuck connections, slow speeds, or authentication errors. Faster than manually toggling in settings.",
            category = Category.NETWORK,
            commands = listOf(
                "svc wifi disable",
                "sleep 2",
                "svc wifi enable",
                "echo 'WiFi restarted'"
            )
        ),
        Script(
            id = "airplane_toggle",
            name = "Toggle Airplane Mode",
            description = "Activates airplane mode for 3 seconds then turns it off. Completely resets all radios: WiFi, mobile data, Bluetooth, NFC. Nuclear option for stubborn connection issues. All connections will be re-established fresh.",
            category = Category.NETWORK,
            commands = listOf(
                "settings put global airplane_mode_on 1",
                "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state true",
                "sleep 3",
                "settings put global airplane_mode_on 0",
                "am broadcast -a android.intent.action.AIRPLANE_MODE --ez state false",
                "echo 'Airplane mode toggled'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // MAINTENANCE
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fstrim",
            name = "TRIM Storage",
            description = "Runs TRIM/discard on your internal storage (SSD/flash). Tells the storage controller which blocks are no longer in use, maintaining write performance over time. Android does this automatically but manual runs can help after large deletions.",
            category = Category.MAINTENANCE,
            commands = listOf(
                "sm fstrim 2>/dev/null || echo 'fstrim not available'",
                "echo 'Storage trimmed'"
            )
        ),
        Script(
            id = "clear_logs",
            name = "Clear System Logs",
            description = "Wipes all system log buffers (main, system, events, radio, crash). Frees a small amount of RAM and starts fresh logs. Run before reproducing a bug if you need clean logs for debugging.",
            category = Category.MAINTENANCE,
            commands = listOf(
                "logcat -c",
                "logcat -b all -c 2>/dev/null || true",
                "echo 'Logs cleared'"
            )
        ),
        Script(
            id = "force_gc",
            name = "Force Garbage Collection",
            description = "Requests all apps to run garbage collection and release unused Java objects from memory. Gentler than killing apps - they remain running but clean up internal memory. Effect varies by app.",
            category = Category.MAINTENANCE,
            commands = listOf(
                "am send-trim-memory --user 0 -a -l COMPLETE 2>/dev/null || true",
                "echo 'GC requested'"
            )
        ),
        Script(
            id = "reboot_soft",
            name = "Soft Reboot",
            description = "⚠️ Restarts Android's system_server process without a full device reboot. Faster than normal reboot but may not be available on all devices. Use when apps are misbehaving and you want a quick refresh.",
            category = Category.MAINTENANCE,
            commands = listOf(
                "setprop ctl.restart zygote 2>/dev/null || echo 'Soft reboot not available'",
                "echo 'Soft reboot initiated'"
            ),
            dangerous = true
        ),
        Script(
            id = "firetv_maintenance",
            name = "Fire TV Maintenance",
            description = "Complete autonomous maintenance: clears streaming app caches (YouTube, Prime, Plex, Tubi, Philo), kills background apps, stops Amazon bloatware and telemetry. Enable periodic scheduling for ZERO INTERVENTION optimization.",
            category = Category.MAINTENANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                // Clear streaming app caches (cache-only, preserves user data)
                "pm clear --cache-only com.amazon.firetv.youtube 2>/dev/null || true",
                "pm clear --cache-only com.amazon.avod 2>/dev/null || true",
                "pm clear --cache-only com.amazon.amazonvideo.livingroom 2>/dev/null || true",
                "pm clear --cache-only com.plexapp.android 2>/dev/null || true",
                "pm clear --cache-only com.tubitv.ott 2>/dev/null || true",
                "pm clear --cache-only com.philo.philo 2>/dev/null || true",
                "pm clear --cache-only com.netflix.ninja 2>/dev/null || true",
                "pm clear --cache-only com.hulu.livingroomplus 2>/dev/null || true",
                // Kill background apps
                "am kill-all",
                // Stop Amazon bloatware
                "am force-stop com.amazon.device.software.ota",
                "am force-stop com.amazon.kindle.cms",
                "am force-stop com.amazon.ods.kindleconnect",
                "am force-stop com.amazon.device.sync",
                "am force-stop com.amazon.firehomerecommendations",
                // Block telemetry (force-stop, not disable - safer)
                "am force-stop com.amazon.device.logmanager",
                "am force-stop com.amazon.metrics.service",
                // Memory pressure
                "am memory-pressure high 2>/dev/null || true",
                "echo 'Fire TV maintenance complete'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV - SECRET MENUS & HIDDEN SETTINGS
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_system_xray",
            name = "Toggle System X-Ray",
            description = "Enables Amazon's hidden performance overlay showing CPU usage, memory, network activity, and frame rate in real-time. Great for debugging streaming issues. Run again to disable.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "current=\$(settings get global debug.sysmon 2>/dev/null); if [ \"\$current\" = \"1\" ]; then settings put global debug.sysmon 0; echo 'System X-Ray DISABLED'; else settings put global debug.sysmon 1; echo 'System X-Ray ENABLED - look for overlay on screen'; fi"
            )
        ),
        Script(
            id = "fire_developer_menu",
            name = "Open Developer Options",
            description = "Launches the hidden Developer Options menu directly. Contains ADB settings, animation scales, GPU rendering options, and more advanced settings.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -a android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                "echo 'Developer Options opened'"
            )
        ),
        Script(
            id = "fire_network_menu",
            name = "Open Network Diagnostics",
            description = "Opens the hidden network diagnostic menu showing detailed WiFi info, signal strength, IP configuration, and connection stats.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -a android.settings.WIFI_SETTINGS",
                "echo 'Network settings opened'"
            )
        ),
        Script(
            id = "fire_storage_menu",
            name = "Open Storage Manager",
            description = "Opens storage settings showing app sizes, cache usage, and lets you clear data. Useful for freeing space on Fire TV's limited storage.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -a android.settings.INTERNAL_STORAGE_SETTINGS",
                "echo 'Storage settings opened'"
            )
        ),
        Script(
            id = "fire_app_manager",
            name = "Open App Manager",
            description = "Opens the full app list showing all installed apps including system apps. Can force stop, clear data, or uninstall apps from here.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -a android.settings.APPLICATION_SETTINGS",
                "echo 'App manager opened'"
            )
        ),
        Script(
            id = "fire_accessibility_menu",
            name = "Open Accessibility Menu",
            description = "Opens hidden accessibility settings with text-to-speech, captions, magnification, and other accessibility features.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -a android.settings.ACCESSIBILITY_SETTINGS",
                "echo 'Accessibility settings opened'"
            )
        ),
        Script(
            id = "fire_date_time",
            name = "Open Date/Time Settings",
            description = "Opens date and time settings. Useful if your Fire TV clock is wrong causing streaming app issues.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -a android.settings.DATE_SETTINGS",
                "echo 'Date/Time settings opened'"
            )
        ),
        Script(
            id = "fire_display_settings",
            name = "Open Display Settings",
            description = "Opens display settings for resolution, HDR, screen calibration, and display sleep options.",
            category = Category.DISPLAY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -a android.settings.DISPLAY_SETTINGS",
                "echo 'Display settings opened'"
            )
        ),
        Script(
            id = "fire_sound_settings",
            name = "Open Sound Settings",
            description = "Opens audio settings for volume, Dolby, surround sound, and audio output configuration.",
            category = Category.AUDIO,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -a android.settings.SOUND_SETTINGS",
                "echo 'Sound settings opened'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV - PERFORMANCE TWEAKS
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_speed_animations",
            name = "Speed Up Animations",
            description = "Sets all animation scales to 0.5x making the UI feel much snappier. Transitions, window animations, and app opening will be twice as fast.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global window_animation_scale 0.5",
                "settings put global transition_animation_scale 0.5",
                "settings put global animator_duration_scale 0.5",
                "echo 'Animations set to 0.5x speed'"
            )
        ),
        Script(
            id = "fire_disable_animations",
            name = "Disable Animations",
            description = "Completely disables all UI animations for maximum performance. The interface will feel instant but less smooth.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global window_animation_scale 0",
                "settings put global transition_animation_scale 0",
                "settings put global animator_duration_scale 0",
                "echo 'All animations disabled'"
            )
        ),
        Script(
            id = "fire_restore_animations",
            name = "Restore Animations",
            description = "Restores all animations to default 1x speed.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global window_animation_scale 1",
                "settings put global transition_animation_scale 1",
                "settings put global animator_duration_scale 1",
                "echo 'Animations restored to default'"
            )
        ),
        Script(
            id = "fire_force_4k",
            name = "Force 4K Resolution",
            description = "Forces Fire TV to output at maximum 4K resolution. Useful if auto-detection isn't working correctly with your TV.",
            category = Category.DISPLAY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "wm size 3840x2160 2>/dev/null || echo 'Could not set resolution'",
                "wm density 320 2>/dev/null || true",
                "echo 'Attempted to set 4K resolution'"
            )
        ),
        Script(
            id = "fire_force_1080p",
            name = "Force 1080p Resolution",
            description = "Forces Fire TV to 1080p. Can improve performance on older Fire TV Sticks that struggle with 4K.",
            category = Category.DISPLAY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "wm size 1920x1080 2>/dev/null || echo 'Could not set resolution'",
                "wm density 240 2>/dev/null || true",
                "echo 'Set to 1080p resolution'"
            )
        ),
        Script(
            id = "fire_reset_resolution",
            name = "Reset Resolution",
            description = "Resets display resolution to auto/default settings.",
            category = Category.DISPLAY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "wm size reset 2>/dev/null || true",
                "wm density reset 2>/dev/null || true",
                "echo 'Resolution reset to default'"
            )
        ),
        Script(
            id = "fire_disable_sleep",
            name = "Disable Sleep Timeout",
            description = "Prevents Fire TV from going to sleep. Useful for digital signage or always-on displays. Warning: may increase power usage.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put system screen_off_timeout 2147483647",
                "settings put secure sleep_timeout 2147483647 2>/dev/null || true",
                "echo 'Sleep timeout disabled (set to max)'"
            )
        ),
        Script(
            id = "fire_enable_sleep_30m",
            name = "Set 30min Sleep",
            description = "Sets Fire TV to sleep after 30 minutes of inactivity.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put system screen_off_timeout 1800000",
                "echo 'Sleep timeout set to 30 minutes'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV - PRIVACY & SECURITY
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_disable_data_monitoring",
            name = "Disable Data Monitoring",
            description = "Disables Amazon's data collection, usage monitoring, and app analytics. Improves privacy significantly.",
            category = Category.PRIVACY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put secure send_action_app_error 0",
                "settings put global device_provisioned 1",
                "pm disable-user --user 0 com.amazon.device.software.ods 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.kindle.devicecontrols 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.ags.app 2>/dev/null || true",
                "echo 'Data monitoring disabled'"
            )
        ),
        Script(
            id = "fire_disable_voice_collection",
            name = "Disable Voice Data",
            description = "Disables Alexa voice history collection and prevents voice recordings from being stored or sent to Amazon.",
            category = Category.PRIVACY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm disable-user --user 0 com.amazon.dee.app 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.vizzini 2>/dev/null || true",
                "settings put secure voice_interaction_service '' 2>/dev/null || true",
                "echo 'Voice data collection disabled'"
            )
        ),
        Script(
            id = "fire_enable_unknown_sources",
            name = "Enable Unknown Sources",
            description = "Enables installation of apps from unknown sources (sideloading). Required to install APKs from Downloader or USB.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put secure install_non_market_apps 1",
                "settings put global verifier_verify_adb_installs 0",
                "echo 'Unknown sources ENABLED - you can now sideload APKs'"
            )
        ),
        Script(
            id = "fire_disable_unknown_sources",
            name = "Disable Unknown Sources",
            description = "Disables sideloading for better security.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put secure install_non_market_apps 0",
                "echo 'Unknown sources DISABLED'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV - APP MANAGEMENT
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_clear_all_caches",
            name = "Clear ALL App Caches",
            description = "Clears cache for all installed apps at once. Can free up significant storage space. Won't delete your logins or preferences.",
            category = Category.CACHE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm list packages -3 | cut -d: -f2 | while read pkg; do pm clear --cache-only \$pkg 2>/dev/null; done",
                "pm list packages -s | cut -d: -f2 | while read pkg; do pm clear --cache-only \$pkg 2>/dev/null; done",
                "echo 'All app caches cleared'"
            )
        ),
        Script(
            id = "fire_list_sideloaded",
            name = "List Sideloaded Apps",
            description = "Shows all third-party (sideloaded) apps installed on your Fire TV.",
            category = Category.DIAGNOSTICS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "echo '=== Sideloaded Apps ==='",
                "pm list packages -3 | cut -d: -f2 | while read pkg; do echo \"• \$pkg\"; done",
                "echo ''",
                "echo \"Total: \$(pm list packages -3 | wc -l) apps\""
            )
        ),
        Script(
            id = "fire_list_disabled",
            name = "List Disabled Apps",
            description = "Shows all apps that have been disabled. Useful to see what bloatware you've already removed.",
            category = Category.DIAGNOSTICS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "echo '=== Disabled Apps ==='",
                "pm list packages -d | cut -d: -f2 | while read pkg; do echo \"• \$pkg\"; done",
                "echo ''",
                "echo \"Total: \$(pm list packages -d | wc -l) disabled\""
            )
        ),
        Script(
            id = "fire_launch_kodi",
            name = "Launch Kodi",
            description = "Directly launches Kodi if installed. Useful for quick access without navigating the Fire TV interface.",
            category = Category.QUICK_ACTIONS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -n org.xbmc.kodi/.Splash 2>/dev/null || am start -n org.xbmc.kodi/.Main 2>/dev/null || echo 'Kodi not installed'"
            )
        ),
        Script(
            id = "fire_launch_plex",
            name = "Launch Plex",
            description = "Directly launches Plex if installed.",
            category = Category.QUICK_ACTIONS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -n com.plexapp.android/.activities.SplashActivity 2>/dev/null || echo 'Plex not installed'"
            )
        ),
        Script(
            id = "fire_launch_downloader",
            name = "Launch Downloader",
            description = "Launches the Downloader app - essential for sideloading APKs on Fire TV.",
            category = Category.QUICK_ACTIONS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -n com.esaba.downloader/.MainActivity 2>/dev/null || echo 'Downloader not installed - get it from Amazon App Store'"
            )
        ),
        Script(
            id = "fire_reboot",
            name = "Reboot Fire TV",
            description = "⚠️ Immediately reboots your Fire TV. Make sure you've saved any work.",
            category = Category.MAINTENANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            dangerous = true,
            commands = listOf(
                "reboot"
            )
        ),
        Script(
            id = "fire_network_info",
            name = "Network Information",
            description = "Shows detailed network info: IP address, MAC address, WiFi signal strength, DNS servers, and gateway.",
            category = Category.DIAGNOSTICS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "echo '=== Network Info ==='",
                "echo \"IP Address: \$(ip route get 1 | awk '{print \$7}' 2>/dev/null || echo 'Unknown')\"",
                "echo \"Gateway: \$(ip route | grep default | awk '{print \$3}' 2>/dev/null || echo 'Unknown')\"",
                "echo \"DNS: \$(getprop net.dns1) / \$(getprop net.dns2)\"",
                "echo ''",
                "echo '=== WiFi ==='",
                "dumpsys wifi | grep -E 'mWifiInfo|SSID|RSSI|Link speed' | head -10 2>/dev/null || echo 'WiFi info unavailable'"
            )
        ),
        Script(
            id = "fire_temp_check",
            name = "Check Temperature",
            description = "Shows Fire TV's current temperature. High temps (>70°C) can cause throttling and buffering issues.",
            category = Category.DIAGNOSTICS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "echo '=== Device Temperature ==='",
                "cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | while read temp; do echo \"\$((\$temp / 1000))°C\"; done | head -3",
                "echo ''",
                "dumpsys thermalservice 2>/dev/null | grep -E 'Temperature|mThrottling' | head -5 || echo 'Thermal service unavailable'"
            )
        ),
        Script(
            id = "fire_ram_boost",
            name = "RAM Boost",
            description = "Aggressively frees up RAM by killing background apps, dropping caches, and requesting memory compaction. Good for before gaming or heavy streaming.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am kill-all",
                "sync",
                "echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true",
                "am memory-pressure high 2>/dev/null || true",
                "echo '=== Memory Status ==='",
                "cat /proc/meminfo | grep -E 'MemTotal|MemFree|MemAvailable|Cached' | head -4",
                "echo 'RAM boost complete'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // DIAGNOSTICS
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "system_info",
            name = "System Information",
            description = "Complete device overview: model, manufacturer, Android version, SDK level, security patch date, total/available RAM, and storage space. Essential diagnostic info for troubleshooting or when someone asks about your device specs.",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "echo '=== Device ==='",
                "echo \"Model: \$(getprop ro.product.model)\"",
                "echo \"Manufacturer: \$(getprop ro.product.manufacturer)\"",
                "echo \"Android: \$(getprop ro.build.version.release) (SDK \$(getprop ro.build.version.sdk))\"",
                "echo \"Security Patch: \$(getprop ro.build.version.security_patch)\"",
                "echo ''",
                "echo '=== Memory ==='",
                "cat /proc/meminfo | grep -E 'MemTotal|MemFree|MemAvailable'",
                "echo ''",
                "echo '=== Storage ==='",
                "df -h /data | tail -1"
            )
        ),
        Script(
            id = "battery_info",
            name = "Battery Status",
            description = "Detailed battery report: current level, charging status (AC/USB/wireless), battery health rating, temperature in tenths of degrees (divide by 10 for Celsius), and voltage. Useful for diagnosing battery or charging issues.",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "dumpsys battery | grep -E 'level|status|health|temperature|voltage'"
            )
        ),
        Script(
            id = "cpu_info",
            name = "CPU Information",
            description = "Shows CPU core count, current frequencies for each core, and top processes by CPU usage. Useful for identifying apps that are consuming too much processing power or checking if your CPU is throttling.",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "echo '=== CPU Cores ==='",
                "cat /proc/cpuinfo | grep 'processor' | wc -l | xargs echo 'Cores:'",
                "echo ''",
                "echo '=== Current Frequencies ==='",
                "for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq; do cat \$cpu 2>/dev/null | xargs -I{} echo \"{}Hz\"; done | head -4",
                "echo ''",
                "echo '=== Top Processes ==='",
                "top -n 1 -m 5 2>/dev/null | head -12 || ps -eo pid,comm,%cpu --sort=-%cpu | head -6"
            )
        ),
        Script(
            id = "storage_usage",
            name = "Storage Usage",
            description = "Lists your biggest storage hogs - apps ranked by how much space their data folders consume. Finds apps with bloated caches, large offline downloads, or excessive data accumulation. Top 10 biggest are shown.",
            category = Category.DIAGNOSTICS,
            requiresRoot = true,
            commands = listOf(
                "echo '=== App Storage Usage ==='",
                "du -sh /data/data/* 2>/dev/null | sort -hr | head -10"
            )
        ),
        Script(
            id = "running_services",
            name = "Running Services",
            description = "Shows all background services currently running on your device with total count. Reveals hidden background activity from apps you thought were closed. Useful for finding battery drains or privacy-invading services.",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "dumpsys activity services | grep 'ServiceRecord{' | wc -l | xargs echo 'Total services:'",
                "echo ''",
                "dumpsys activity services | grep 'ServiceRecord{' | head -15"
            )
        ),
        Script(
            id = "screen_info",
            name = "Screen Information",
            description = "Displays current screen resolution, DPI density, and refresh rate. Shows both physical resolution and any override values. Useful for checking display settings or troubleshooting UI scaling issues.",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "echo '=== Display ==='",
                "wm size",
                "wm density",
                "echo ''",
                "echo '=== Refresh Rate ==='",
                "dumpsys display | grep 'mDisplayModeSpecs' | head -1 || dumpsys SurfaceFlinger | grep 'refresh-rate' | head -1"
            )
        ),
        Script(
            id = "sensor_list",
            name = "Sensor List",
            description = "Shows all hardware sensors on your device: accelerometer, gyroscope, proximity, light sensor, magnetometer, barometer, and more. Lists sensor types, vendors, and capabilities. Useful for checking hardware features.",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "dumpsys sensorservice | grep 'Sensor' | head -20"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // DEVELOPER
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "enable_dev_options",
            name = "Enable Dev Options",
            description = "Unlocks the Developer Options menu in Settings without having to tap the build number 7 times. Gives access to USB debugging, animation controls, GPU profiling, and other advanced settings.",
            category = Category.DEVELOPER,
            commands = listOf(
                "settings put global development_settings_enabled 1",
                "echo 'Developer options enabled'"
            )
        ),
        Script(
            id = "enable_usb_debugging",
            name = "Enable USB Debugging",
            description = "Enables ADB (Android Debug Bridge) access over USB. Required for connecting to a computer for app development, file transfers, or running shell commands. Security note: Only enable when needed.",
            category = Category.DEVELOPER,
            commands = listOf(
                "settings put global adb_enabled 1",
                "echo 'USB debugging enabled'"
            )
        ),
        Script(
            id = "enable_wireless_adb",
            name = "Enable Wireless ADB",
            description = "Enables ADB connections over WiFi on port 5555. Connect from computer with 'adb connect [phone-IP]:5555'. Useful for debugging without USB cable or controlling your phone remotely. Disable when not needed for security.",
            category = Category.DEVELOPER,
            commands = listOf(
                "setprop service.adb.tcp.port 5555",
                "stop adbd",
                "start adbd",
                "echo 'Wireless ADB enabled on port 5555'"
            )
        ),
        Script(
            id = "show_layout_bounds",
            name = "Show Layout Bounds",
            description = "Draws colored rectangles around every UI element showing their exact boundaries, margins, and padding. Essential for app developers debugging layout issues. Toggle apps to see the effect immediately.",
            category = Category.DEVELOPER,
            commands = listOf(
                "setprop debug.layout true",
                "service call activity 1599295570 2>/dev/null || true",
                "echo 'Layout bounds enabled - toggle apps to see effect'"
            )
        ),
        Script(
            id = "hide_layout_bounds",
            name = "Hide Layout Bounds",
            description = "Turns off the layout bounds visualization, returning apps to their normal appearance. Run this after you're done debugging UI issues.",
            category = Category.DEVELOPER,
            commands = listOf(
                "setprop debug.layout false",
                "service call activity 1599295570 2>/dev/null || true",
                "echo 'Layout bounds disabled'"
            )
        ),
        Script(
            id = "show_touches",
            name = "Show Touches",
            description = "Shows a white dot wherever you touch the screen. Useful for screen recordings, demonstrations, or verifying touch responsiveness. The dot follows your finger in real-time.",
            category = Category.DEVELOPER,
            commands = listOf(
                "settings put system show_touches 1",
                "echo 'Touch indicators enabled'"
            )
        ),
        Script(
            id = "hide_touches",
            name = "Hide Touches",
            description = "Turns off the touch visualization dots. Run this after finishing your screen recording or demonstration to return to normal touch behavior.",
            category = Category.DEVELOPER,
            commands = listOf(
                "settings put system show_touches 0",
                "echo 'Touch indicators disabled'"
            )
        ),
        Script(
            id = "show_pointer_location",
            name = "Show Pointer Location",
            description = "Displays crosshairs at touch point with exact X/Y coordinates, pressure, and touch size. Shows a bar at top with velocity and gesture tracking. Useful for debugging touch issues or testing digitizer accuracy.",
            category = Category.DEVELOPER,
            commands = listOf(
                "settings put system pointer_location 1",
                "echo 'Pointer location enabled'"
            )
        ),
        Script(
            id = "hide_pointer_location",
            name = "Hide Pointer Location",
            description = "Removes the pointer coordinate overlay from the screen. Run this to return to normal operation after debugging touch input.",
            category = Category.DEVELOPER,
            commands = listOf(
                "settings put system pointer_location 0",
                "echo 'Pointer location disabled'"
            )
        ),
        Script(
            id = "gpu_overdraw_on",
            name = "Show GPU Overdraw",
            description = "Color-codes the screen to show where pixels are drawn multiple times: blue (1x overdraw), green (2x), pink (3x), red (4x). Helps developers optimize rendering performance by finding redundant drawing operations.",
            category = Category.DEVELOPER,
            commands = listOf(
                "setprop debug.hwui.overdraw show",
                "service call activity 1599295570 2>/dev/null || true",
                "echo 'GPU overdraw visualization enabled'"
            )
        ),
        Script(
            id = "gpu_overdraw_off",
            name = "Hide GPU Overdraw",
            description = "Turns off the GPU overdraw color visualization, returning the display to normal. Use after analyzing rendering performance.",
            category = Category.DEVELOPER,
            commands = listOf(
                "setprop debug.hwui.overdraw false",
                "service call activity 1599295570 2>/dev/null || true",
                "echo 'GPU overdraw visualization disabled'"
            )
        ),
        Script(
            id = "force_gpu_rendering",
            name = "Force GPU Rendering",
            description = "Forces all apps to use GPU hardware acceleration even if they don't request it. Can improve performance in older apps but may cause visual glitches in apps designed for software rendering.",
            category = Category.DEVELOPER,
            commands = listOf(
                "settings put global debug.hwui.renderer opengl",
                "setprop debug.hwui.render_dirty_regions false",
                "echo 'GPU rendering forced'"
            )
        ),
        Script(
            id = "strict_mode_visual",
            name = "Enable StrictMode Flash",
            description = "Flashes the screen red when any app performs slow operations (disk read/write, network calls) on the UI thread. Helps developers identify performance problems that cause UI jank or freezing.",
            category = Category.DEVELOPER,
            commands = listOf(
                "settings put global strict_mode_visual_enabled 1",
                "echo 'StrictMode visual indicator enabled'"
            )
        ),
        Script(
            id = "aggressive_doze",
            name = "Enable Aggressive Doze",
            description = "Forces the device into deep sleep (Doze) mode immediately without waiting for the normal inactivity period. Apps lose network access and background work is deferred. Maximum battery savings at the cost of notification delays.",
            category = Category.DEVELOPER,
            commands = listOf(
                "dumpsys deviceidle enable all",
                "dumpsys deviceidle force-idle",
                "echo 'Aggressive doze enabled'"
            )
        ),
        Script(
            id = "disable_doze",
            name = "Disable Doze",
            description = "Takes the device out of forced Doze mode and disables aggressive sleep. Apps regain normal background access and notifications arrive immediately. Use if aggressive doze was causing issues.",
            category = Category.DEVELOPER,
            commands = listOf(
                "dumpsys deviceidle unforce",
                "dumpsys deviceidle disable",
                "echo 'Doze mode disabled'"
            )
        ),
        Script(
            id = "logcat_errors",
            name = "Show Recent Errors",
            description = "Shows the last 30 error-level log entries from the system. Displays crashes, exceptions, and serious issues from all apps. First step in diagnosing why an app is misbehaving.",
            category = Category.DEVELOPER,
            commands = listOf(
                "logcat -d -v brief *:E | tail -30"
            )
        ),
        Script(
            id = "logcat_crashes",
            name = "Show Crashes",
            description = "Filters logs specifically for app crashes (FATAL exceptions and AndroidRuntime errors). Shows the last 20 crash events with stack traces. Essential for debugging why an app keeps force-closing.",
            category = Category.DEVELOPER,
            commands = listOf(
                "logcat -d -v brief | grep -E 'FATAL|AndroidRuntime|CRASH' | tail -20"
            )
        ),
        Script(
            id = "bugreport",
            name = "Generate Bug Report",
            description = "⚠️ Creates a comprehensive system dump including logs, system state, app data, and debugging info. Large file, may take several minutes. Typically used when reporting bugs to Google or device manufacturers.",
            category = Category.DEVELOPER,
            commands = listOf(
                "bugreportz 2>/dev/null || bugreport 2>/dev/null || echo 'Bug report requires shell user'"
            ),
            dangerous = true
        ),

        // ═══════════════════════════════════════════════════════════════
        // SECURITY / AUDIT
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "check_root",
            name = "Check Root Status",
            description = "Scans for root access: checks for su binary in common paths, Magisk installation, and root-related files. Reports whether your device is rooted and which method was used (Magisk, SuperSU, etc.).",
            category = Category.SECURITY,
            commands = listOf(
                "echo '=== Root Check ==='",
                "which su && echo 'su binary found' || echo 'su binary not found'",
                "ls -la /system/xbin/su /system/bin/su /sbin/su 2>/dev/null || echo 'No su in common paths'",
                "echo ''",
                "echo '=== Magisk Check ==='",
                "pm list packages | grep magisk && echo 'Magisk found' || echo 'No Magisk'",
                "ls -la /data/adb/magisk 2>/dev/null || echo 'No Magisk data'"
            )
        ),
        Script(
            id = "selinux_status",
            name = "SELinux Status",
            description = "Checks Android's Security-Enhanced Linux mode: Enforcing (secure, blocking violations), Permissive (logging only), or Disabled. Permissive/Disabled may indicate root or security modifications.",
            category = Category.SECURITY,
            commands = listOf(
                "getenforce",
                "cat /sys/fs/selinux/enforce 2>/dev/null || echo 'Cannot read SELinux status'"
            )
        ),
        Script(
            id = "dangerous_permissions",
            name = "Apps with Dangerous Perms",
            description = "Security audit showing which apps have access to your camera, microphone, and precise location. Lists package names with these sensitive permissions granted. Review for apps that shouldn't have such access.",
            category = Category.SECURITY,
            commands = listOf(
                "echo '=== Camera Access ==='",
                "dumpsys package | grep -B5 'android.permission.CAMERA.*granted=true' | grep 'Package \\[' | head -10",
                "echo ''",
                "echo '=== Microphone Access ==='",
                "dumpsys package | grep -B5 'android.permission.RECORD_AUDIO.*granted=true' | grep 'Package \\[' | head -10",
                "echo ''",
                "echo '=== Location Access ==='",
                "dumpsys package | grep -B5 'android.permission.ACCESS_FINE_LOCATION.*granted=true' | grep 'Package \\[' | head -10"
            )
        ),
        Script(
            id = "installed_certs",
            name = "List Installed Certificates",
            description = "Shows manually installed root CA certificates that could intercept encrypted traffic. User-added CAs are security-relevant - they can enable MITM attacks. Also shows system CA count for reference.",
            category = Category.SECURITY,
            commands = listOf(
                "ls -la /data/misc/user/0/cacerts-added/ 2>/dev/null || echo 'No user CA certs installed'",
                "echo ''",
                "echo '=== System CAs ==='",
                "ls /system/etc/security/cacerts/ 2>/dev/null | wc -l | xargs echo 'System CA count:'"
            )
        ),
        Script(
            id = "device_admin_apps",
            name = "Device Admin Apps",
            description = "Shows apps granted Device Administrator privileges - powerful permissions that can lock the device, wipe data, or enforce policies. Common for MDM/work apps. Review for suspicious or unknown entries.",
            category = Category.SECURITY,
            commands = listOf(
                "dumpsys device_policy | grep -A2 'Admin #' | head -20"
            )
        ),
        Script(
            id = "unknown_sources_status",
            name = "Unknown Sources Status",
            description = "Checks whether apps can be installed from outside the Play Store. If enabled (1), your device can install APKs from any source - convenient but less secure. Also shows if ADB install verification is on.",
            category = Category.SECURITY,
            commands = listOf(
                "settings get secure install_non_market_apps",
                "settings get global verifier_verify_adb_installs"
            )
        ),
        Script(
            id = "accessibility_services",
            name = "Active Accessibility Services",
            description = "⚠️ Shows apps with Accessibility permissions - these can read screen content, perform taps, and monitor all activity. Legitimate uses include password managers, but malware often abuses this. Review any unknown entries.",
            category = Category.SECURITY,
            commands = listOf(
                "settings get secure enabled_accessibility_services"
            )
        ),
        Script(
            id = "adb_keys",
            name = "Authorized ADB Keys",
            description = "Lists computers authorized to connect via ADB - each entry is a computer you previously approved. Unknown keys could indicate unauthorized access. Clear in Developer Options to revoke all authorizations.",
            category = Category.SECURITY,
            commands = listOf(
                "cat /data/misc/adb/adb_keys 2>/dev/null || echo 'Cannot read ADB keys'"
            )
        ),
        Script(
            id = "open_ports",
            name = "Open Network Ports",
            description = "Scans for open TCP and UDP ports on your device. Open ports can indicate services accepting network connections - expected for ADB (5555) but suspicious if unknown ports appear. Security reconnaissance tool.",
            category = Category.SECURITY,
            commands = listOf(
                "echo '=== Listening TCP Ports ==='",
                "cat /proc/net/tcp | awk 'NR>1 {print \$2}' | cut -d: -f2 | sort -u | while read hex; do printf '%d\\n' 0x\$hex; done | sort -n | uniq",
                "echo ''",
                "echo '=== Listening UDP Ports ==='",
                "cat /proc/net/udp | awk 'NR>1 {print \$2}' | cut -d: -f2 | sort -u | while read hex; do printf '%d\\n' 0x\$hex; done | sort -n | uniq"
            )
        ),
        Script(
            id = "network_connections",
            name = "Active Connections",
            description = "Displays all active network connections showing local and remote IP addresses. Reveals what servers your apps are communicating with. Useful for detecting suspicious network activity or data exfiltration.",
            category = Category.SECURITY,
            commands = listOf(
                "netstat -tunp 2>/dev/null | head -30 || cat /proc/net/tcp | head -20"
            )
        ),
        Script(
            id = "check_debuggable_apps",
            name = "Debuggable Apps",
            description = "Finds apps built with android:debuggable=true - a development flag that should never ship in production. Debuggable apps can be easily reverse-engineered and exploited. Flag suspicious if found in non-dev apps.",
            category = Category.SECURITY,
            commands = listOf(
                "for pkg in \$(pm list packages -3 | cut -d: -f2); do dumpsys package \$pkg | grep -q 'flags=.*DEBUGGABLE' && echo \$pkg; done"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // DISPLAY
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "screen_on",
            name = "Turn Screen On",
            description = "Sends a wake-up signal to turn on the screen, equivalent to pressing the power button. Useful for remote control scenarios or automation when you can't physically touch the device.",
            category = Category.DISPLAY,
            commands = listOf(
                "input keyevent KEYCODE_WAKEUP",
                "echo 'Screen wake sent'"
            )
        ),
        Script(
            id = "screen_off",
            name = "Turn Screen Off",
            description = "Puts the device to sleep, turning off the screen like pressing the power button. Device remains running with WiFi active. Use for quick screen-off without locking.",
            category = Category.DISPLAY,
            commands = listOf(
                "input keyevent KEYCODE_SLEEP",
                "echo 'Screen sleep sent'"
            )
        ),
        Script(
            id = "brightness_max",
            name = "Brightness Max",
            description = "Disables auto-brightness and sets manual brightness to 100%. Maximum visibility for outdoor use or sunny conditions. Will drain battery faster. Use brightness_auto to restore adaptive brightness.",
            category = Category.DISPLAY,
            commands = listOf(
                "settings put system screen_brightness_mode 0",
                "settings put system screen_brightness 255",
                "echo 'Brightness set to max'"
            )
        ),
        Script(
            id = "brightness_min",
            name = "Brightness Min",
            description = "Disables auto-brightness and sets manual brightness to nearly zero. Perfect for nighttime use or dark rooms. Saves battery. May be difficult to see in bright environments.",
            category = Category.DISPLAY,
            commands = listOf(
                "settings put system screen_brightness_mode 0",
                "settings put system screen_brightness 10",
                "echo 'Brightness set to min'"
            )
        ),
        Script(
            id = "brightness_auto",
            name = "Brightness Auto",
            description = "Enables adaptive brightness that adjusts based on ambient light sensor. The recommended setting - balances visibility with battery life automatically as lighting conditions change.",
            category = Category.DISPLAY,
            commands = listOf(
                "settings put system screen_brightness_mode 1",
                "echo 'Auto brightness enabled'"
            )
        ),
        Script(
            id = "screen_timeout_30s",
            name = "Screen Timeout 30s",
            description = "Screen turns off after 30 seconds of inactivity. Good for security and battery life - prevents burn-in on OLED screens and accidental touches when phone is left unlocked.",
            category = Category.DISPLAY,
            commands = listOf(
                "settings put system screen_off_timeout 30000",
                "echo 'Screen timeout set to 30 seconds'"
            )
        ),
        Script(
            id = "screen_timeout_5m",
            name = "Screen Timeout 5m",
            description = "Screen stays on for 5 minutes before sleeping. Useful when reading or following instructions where you need the screen visible but aren't actively touching it.",
            category = Category.DISPLAY,
            commands = listOf(
                "settings put system screen_off_timeout 300000",
                "echo 'Screen timeout set to 5 minutes'"
            )
        ),
        Script(
            id = "screen_timeout_never",
            name = "Screen Always On",
            description = "⚠️ Screen never turns off automatically. Use for navigation, presentations, or digital signage. Warning: Can cause OLED burn-in and drains battery quickly. Remember to turn off manually or reset timeout.",
            category = Category.DISPLAY,
            commands = listOf(
                "settings put system screen_off_timeout 2147483647",
                "svc power stayon true 2>/dev/null || true",
                "echo 'Screen timeout disabled'"
            )
        ),
        Script(
            id = "rotation_portrait",
            name = "Lock Portrait",
            description = "Disables auto-rotate and locks screen to portrait (vertical) orientation. Screen won't flip when you tilt the phone. Useful for reading in bed or when auto-rotate is annoying.",
            category = Category.DISPLAY,
            commands = listOf(
                "settings put system accelerometer_rotation 0",
                "settings put system user_rotation 0",
                "echo 'Locked to portrait'"
            )
        ),
        Script(
            id = "rotation_landscape",
            name = "Lock Landscape",
            description = "Disables auto-rotate and locks screen to landscape (horizontal) orientation. Great for watching videos or using apps that work better in widescreen mode.",
            category = Category.DISPLAY,
            commands = listOf(
                "settings put system accelerometer_rotation 0",
                "settings put system user_rotation 1",
                "echo 'Locked to landscape'"
            )
        ),
        Script(
            id = "rotation_auto",
            name = "Auto Rotation",
            description = "Enables automatic screen rotation based on accelerometer. Screen orientation follows how you hold the phone. Default behavior for most users.",
            category = Category.DISPLAY,
            commands = listOf(
                "settings put system accelerometer_rotation 1",
                "echo 'Auto rotation enabled'"
            )
        ),
        Script(
            id = "night_mode_on",
            name = "Dark Mode On",
            description = "Switches system to dark theme. Apps that support dark mode will show dark backgrounds and light text. Reduces eye strain in low light and saves battery on OLED screens.",
            category = Category.DISPLAY,
            commands = listOf(
                "cmd uimode night yes",
                "echo 'Dark mode enabled'"
            )
        ),
        Script(
            id = "night_mode_off",
            name = "Dark Mode Off",
            description = "Switches back to light theme with white/light backgrounds. Better visibility in bright sunlight. Apps will show their default light color schemes.",
            category = Category.DISPLAY,
            commands = listOf(
                "cmd uimode night no",
                "echo 'Dark mode disabled'"
            )
        ),
        Script(
            id = "resolution_hd",
            name = "Resolution HD",
            description = "Reduces screen resolution to 720p (1280x720). Dramatically improves performance and battery life on high-resolution devices. UI elements appear larger. Good for gaming on weaker phones.",
            category = Category.DISPLAY,
            commands = listOf(
                "wm size 1280x720",
                "echo 'Resolution set to 720p'"
            )
        ),
        Script(
            id = "resolution_fhd",
            name = "Resolution FHD",
            description = "Sets screen to Full HD 1080p (1920x1080). Good balance between sharpness and performance. Standard resolution for most content and a reasonable battery compromise.",
            category = Category.DISPLAY,
            commands = listOf(
                "wm size 1920x1080",
                "echo 'Resolution set to 1080p'"
            )
        ),
        Script(
            id = "resolution_reset",
            name = "Resolution Reset",
            description = "Restores screen to its native (physical) resolution and density. Undoes any resolution changes and returns to maximum sharpness. Use if UI looks wrong after resolution experiments.",
            category = Category.DISPLAY,
            commands = listOf(
                "wm size reset",
                "wm density reset",
                "echo 'Resolution reset to native'"
            )
        ),
        Script(
            id = "refresh_rate_60",
            name = "Refresh Rate 60Hz",
            description = "Locks screen refresh to 60Hz (standard rate). Significantly extends battery life on high-refresh phones (90Hz/120Hz). Scrolling will be slightly less smooth but most won't notice.",
            category = Category.DISPLAY,
            commands = listOf(
                "settings put system peak_refresh_rate 60.0",
                "settings put system min_refresh_rate 60.0",
                "echo 'Refresh rate set to 60Hz'"
            )
        ),
        Script(
            id = "refresh_rate_120",
            name = "Refresh Rate 120Hz",
            description = "Forces screen to maximum 120Hz refresh rate. Ultra-smooth scrolling and animations. Gaming and social media feel buttery smooth. Trades battery life for fluidity. Only works on 120Hz-capable screens.",
            category = Category.DISPLAY,
            commands = listOf(
                "settings put system peak_refresh_rate 120.0",
                "settings put system min_refresh_rate 120.0",
                "echo 'Refresh rate set to 120Hz'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // AUDIO
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "volume_max",
            name = "Volume Max",
            description = "Cranks all audio streams to maximum: media/music, ringtone, and alarm volumes. ⚠️ Warning: May be loud! Use before connecting to Bluetooth speaker or when you need maximum output.",
            category = Category.AUDIO,
            commands = listOf(
                "cmd media_session volume --stream 3 --set 15",  // Media
                "cmd media_session volume --stream 2 --set 7",   // Ring
                "cmd media_session volume --stream 1 --set 7",   // Alarm
                "echo 'Volume set to max'"
            )
        ),
        Script(
            id = "volume_mute",
            name = "Mute All",
            description = "Silences media playback, ringtone, and notification sounds. Quick way to go completely silent for meetings, movies, or sleeping. Alarms may still sound depending on your DND settings.",
            category = Category.AUDIO,
            commands = listOf(
                "cmd media_session volume --stream 3 --set 0",
                "cmd media_session volume --stream 2 --set 0",
                "cmd media_session volume --stream 5 --set 0",
                "echo 'Audio muted'"
            )
        ),
        Script(
            id = "dnd_on",
            name = "Do Not Disturb On",
            description = "Activates Do Not Disturb - silences calls, notifications, and alerts. Starred contacts and alarms can still break through (configurable in settings). Perfect for sleeping or focused work.",
            category = Category.AUDIO,
            commands = listOf(
                "cmd notification set_dnd on 2>/dev/null || settings put global zen_mode 1",
                "echo 'Do Not Disturb enabled'"
            )
        ),
        Script(
            id = "dnd_off",
            name = "Do Not Disturb Off",
            description = "Turns off Do Not Disturb mode, allowing all notifications, calls, and alerts to come through normally. Use when you're ready to receive interruptions again.",
            category = Category.AUDIO,
            commands = listOf(
                "cmd notification set_dnd off 2>/dev/null || settings put global zen_mode 0",
                "echo 'Do Not Disturb disabled'"
            )
        ),
        Script(
            id = "ringer_vibrate",
            name = "Ringer Vibrate",
            description = "Enables vibrate mode with no ringtone sound. Phone vibrates for calls and messages. Good for meetings, libraries, or anywhere you need to be aware of calls without disturbing others.",
            category = Category.AUDIO,
            deviceTypes = setOf(DeviceType.PHONE),
            commands = listOf(
                "settings put system vibrate_when_ringing 1",
                "cmd media_session volume --stream 2 --set 0",
                "echo 'Set to vibrate'"
            )
        ),
        Script(
            id = "ringer_normal",
            name = "Ringer Normal",
            description = "Restores normal ringer mode with audible ringtone at medium volume and vibration disabled. Standard phone operation - you'll hear calls and notifications at reasonable volume.",
            category = Category.AUDIO,
            deviceTypes = setOf(DeviceType.PHONE),
            commands = listOf(
                "cmd media_session volume --stream 2 --set 5",
                "settings put system vibrate_when_ringing 0",
                "echo 'Ringer set to normal'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // QUICK ACTIONS
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "screenshot",
            name = "Take Screenshot",
            description = "Captures the current screen to a PNG file in /sdcard with timestamp filename. Use for documentation, bug reports, or saving what's on screen. Find images in your Downloads or DCIM folder.",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "screencap -p /sdcard/screenshot_\$(date +%Y%m%d_%H%M%S).png",
                "echo 'Screenshot saved to /sdcard'"
            )
        ),
        Script(
            id = "screenrecord_start",
            name = "Start Screen Recording",
            description = "Records your screen to an MP4 video file (30 second limit). Runs in background while you use your phone. Great for tutorials, bug demos, or capturing gameplay. File saved to /sdcard.",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "screenrecord --time-limit 30 /sdcard/recording_\$(date +%Y%m%d_%H%M%S).mp4 &",
                "echo 'Recording started (30 sec max)'"
            )
        ),
        Script(
            id = "open_settings",
            name = "Open Settings",
            description = "Launches the main Settings app. Quick access to all device configuration options including WiFi, Bluetooth, display, sound, and system preferences.",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "am start -a android.settings.SETTINGS",
                "echo 'Settings opened'"
            )
        ),
        Script(
            id = "open_dev_settings",
            name = "Open Developer Options",
            description = "Opens developer options settings",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "am start -a com.android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                "echo 'Developer options opened'"
            )
        ),
        Script(
            id = "open_wifi_settings",
            name = "Open WiFi Settings",
            description = "Opens WiFi settings",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "am start -a android.settings.WIFI_SETTINGS",
                "echo 'WiFi settings opened'"
            )
        ),
        Script(
            id = "open_bluetooth_settings",
            name = "Open Bluetooth Settings",
            description = "Opens Bluetooth settings",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "am start -a android.settings.BLUETOOTH_SETTINGS",
                "echo 'Bluetooth settings opened'"
            )
        ),
        Script(
            id = "open_battery_settings",
            name = "Open Battery Settings",
            description = "Opens battery/power settings",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "am start -a android.intent.action.POWER_USAGE_SUMMARY",
                "echo 'Battery settings opened'"
            )
        ),
        Script(
            id = "open_storage_settings",
            name = "Open Storage Settings",
            description = "Opens storage management",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "am start -a android.settings.INTERNAL_STORAGE_SETTINGS",
                "echo 'Storage settings opened'"
            )
        ),
        Script(
            id = "open_accessibility",
            name = "Open Accessibility",
            description = "Opens accessibility settings",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "am start -a android.settings.ACCESSIBILITY_SETTINGS",
                "echo 'Accessibility settings opened'"
            )
        ),
        Script(
            id = "go_home",
            name = "Go Home",
            description = "Returns to home screen",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "input keyevent KEYCODE_HOME",
                "echo 'Home pressed'"
            )
        ),
        Script(
            id = "press_back",
            name = "Press Back",
            description = "Simulates back button press",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "input keyevent KEYCODE_BACK",
                "echo 'Back pressed'"
            )
        ),
        Script(
            id = "open_recents",
            name = "Open Recents",
            description = "Opens recent apps view",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "input keyevent KEYCODE_APP_SWITCH",
                "echo 'Recents opened'"
            )
        ),
        Script(
            id = "toggle_flashlight",
            name = "Toggle Flashlight",
            description = "Toggles the camera flashlight",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "cmd statusbar expand-settings 2>/dev/null && sleep 0.3 && input tap 540 400 2>/dev/null || echo 'Open quick settings manually for flashlight'",
                "echo 'Flashlight toggled (manual method)'"
            )
        ),
        Script(
            id = "pull_notifications",
            name = "Pull Down Notifications",
            description = "Opens notification shade",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "cmd statusbar expand-notifications",
                "echo 'Notifications expanded'"
            )
        ),
        Script(
            id = "pull_quick_settings",
            name = "Pull Down Quick Settings",
            description = "Opens quick settings panel",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "cmd statusbar expand-settings",
                "echo 'Quick settings expanded'"
            )
        ),
        Script(
            id = "collapse_shade",
            name = "Collapse Notification Shade",
            description = "Closes notification/quick settings panel",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "cmd statusbar collapse",
                "echo 'Shade collapsed'"
            )
        ),
        Script(
            id = "lock_device",
            name = "Lock Device",
            description = "Locks the device screen",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "input keyevent KEYCODE_POWER",
                "echo 'Lock command sent'"
            )
        ),
        Script(
            id = "paste_clipboard",
            name = "Paste Clipboard",
            description = "Pastes current clipboard content",
            category = Category.QUICK_ACTIONS,
            commands = listOf(
                "input keyevent 279",  // KEYCODE_PASTE
                "echo 'Paste command sent'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // EXTRA DIAGNOSTICS
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "wifi_signal",
            name = "WiFi Signal Strength",
            description = "Displays detailed WiFi diagnostics: network name (SSID), signal strength (RSSI in dBm), link speed in Mbps, and frequency band. RSSI closer to 0 is better (-50 is excellent, -80 is weak).",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "dumpsys wifi | grep -E 'mWifiInfo|SSID|RSSI|Link|Frequency' | head -10"
            )
        ),
        Script(
            id = "thermal_status",
            name = "Thermal Status",
            description = "Reads all temperature sensors: CPU cores, GPU, battery, and skin temps. Values in millidegrees Celsius (divide by 1000). Use to diagnose overheating or check temps during heavy use.",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "echo '=== Thermal Zones ==='",
                "for tz in /sys/class/thermal/thermal_zone*/temp; do echo \"\$tz: \$(cat \$tz 2>/dev/null)\"; done | head -10",
                "echo ''",
                "echo '=== Battery Temp ==='",
                "dumpsys battery | grep temperature"
            )
        ),
        Script(
            id = "uptime_info",
            name = "Uptime & Boot",
            description = "Shows device uptime and boot time",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "echo '=== Uptime ==='",
                "uptime",
                "echo ''",
                "echo '=== Boot Time ==='",
                "cat /proc/uptime | awk '{print \"Uptime: \" int(\$1/86400) \"d \" int((\$1%86400)/3600) \"h \" int((\$1%3600)/60) \"m\"}'"
            )
        ),
        Script(
            id = "kernel_info",
            name = "Kernel Information",
            description = "Shows kernel version and details",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "uname -a",
                "echo ''",
                "cat /proc/version"
            )
        ),
        Script(
            id = "build_props",
            name = "Build Properties",
            description = "Shows key system build properties",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "echo '=== Build Info ==='",
                "getprop ro.build.display.id",
                "getprop ro.build.fingerprint",
                "echo ''",
                "echo '=== Hardware ==='",
                "getprop ro.hardware",
                "getprop ro.board.platform",
                "echo ''",
                "echo '=== Bootloader ==='",
                "getprop ro.bootloader",
                "getprop ro.boot.verifiedbootstate 2>/dev/null || echo 'N/A'"
            )
        ),
        Script(
            id = "partition_info",
            name = "Partition Layout",
            description = "Shows storage partition information",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "df -h | grep -E '/data|/system|/vendor|/product'"
            )
        ),
        Script(
            id = "wakelocks",
            name = "Active Wakelocks",
            description = "Shows processes holding wakelocks",
            category = Category.DIAGNOSTICS,
            commands = listOf(
                "dumpsys power | grep -A 20 'Wake Locks:' | head -25"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV SPECIFIC - PERFORMANCE
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_disable_animations",
            name = "Disable Fire TV Animations",
            description = "Removes all transition animations and visual effects. Menu navigation, app switching, and scrolling will feel instant. Great for older Fire TV Sticks that feel sluggish. Makes the interface more responsive at the cost of visual polish.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global window_animation_scale 0",
                "settings put global transition_animation_scale 0",
                "settings put global animator_duration_scale 0",
                "echo 'Fire TV animations disabled'"
            )
        ),
        Script(
            id = "fire_enable_animations",
            name = "Enable Fire TV Animations",
            description = "Restores smooth visual transitions and animations to default settings. Use this to bring back the polished look after testing with animations disabled.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global window_animation_scale 1",
                "settings put global transition_animation_scale 1",
                "settings put global animator_duration_scale 1",
                "echo 'Fire TV animations enabled'"
            )
        ),
        Script(
            id = "fire_gpu_rendering",
            name = "Force GPU Rendering",
            description = "Forces all apps to use hardware GPU acceleration instead of software rendering. Can improve performance in apps that don't properly utilize the GPU. May cause visual glitches in some older apps but generally improves smoothness.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global force_hw_ui 1 2>/dev/null || true",
                "setprop debug.hwui.renderer opengl 2>/dev/null || true",
                "setprop debug.egl.hw 1 2>/dev/null || true",
                "echo 'GPU rendering forced'"
            )
        ),
        Script(
            id = "fire_limit_background",
            name = "Limit Background Apps",
            description = "Restricts background processes to only 2 apps. Frees up RAM on memory-constrained Fire TV Sticks (especially 1GB models). Apps will reload when switched to but active streaming won't be interrupted.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global background_process_limit 2",
                "settings put global always_finish_activities 0",
                "echo 'Background apps limited to 2'"
            )
        ),
        Script(
            id = "fire_performance_boost",
            name = "Fire TV Turbo Mode",
            description = "🚀 MAXIMUM PERFORMANCE: Applies all speed optimizations at once. Kills background apps, removes animations, enables GPU rendering, limits memory usage, and clears RAM. Perfect before watching a demanding stream or playing games.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am kill-all",
                "settings put global window_animation_scale 0",
                "settings put global transition_animation_scale 0",
                "settings put global animator_duration_scale 0",
                "settings put global background_process_limit 2",
                "settings put global force_hw_ui 1 2>/dev/null || true",
                "am send-trim-memory --user 0 -a -l RUNNING_CRITICAL 2>/dev/null || true",
                "echo 'Fire TV Turbo Mode activated'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV SPECIFIC - DEVELOPER / HIDDEN FEATURES
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_enable_dev_mode",
            name = "Enable Developer Mode",
            description = "Unlocks the hidden Developer Options menu in Settings. Enables ADB debugging for sideloading apps, USB/network debugging, and advanced system access. Required for installing apps outside the Amazon App Store.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global development_settings_enabled 1",
                "settings put global adb_enabled 1",
                "settings put global debug_app '' 2>/dev/null || true",
                "settings put global wait_for_debugger 0 2>/dev/null || true",
                "settings put secure show_ime_with_hard_keyboard 1 2>/dev/null || true",
                "echo 'Developer mode enabled'"
            )
        ),
        Script(
            id = "fire_show_cpu_overlay",
            name = "Show CPU Overlay",
            description = "Displays real-time CPU and GPU usage bars on screen. Useful for diagnosing performance issues, identifying apps that consume too many resources, or monitoring system load during streaming.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "setprop debug.hwui.profile true 2>/dev/null || true",
                "settings put global show_cpu_usage 1 2>/dev/null || true",
                "echo 'CPU overlay enabled - may need restart'"
            )
        ),
        Script(
            id = "fire_show_touches",
            name = "Show Touch Input",
            description = "Shows visual feedback for all remote button presses and D-pad navigation. Displays crosshairs and coordinates on screen. Helpful for troubleshooting remote issues or demonstrating Fire TV to others.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put system show_touches 1",
                "settings put system pointer_location 1 2>/dev/null || true",
                "echo 'Touch input visualization enabled'"
            )
        ),
        Script(
            id = "fire_enable_adb_wifi",
            name = "ADB Over WiFi (Permanent)",
            description = "Enables wireless ADB connections on port 5555. Connect from your computer with 'adb connect [FireTV-IP]:5555'. Persists across reboots. Essential for sideloading apps, running scripts, and remote management without USB.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "setprop service.adb.tcp.port 5555",
                "setprop persist.adb.tcp.port 5555 2>/dev/null || true",
                "stop adbd",
                "start adbd",
                "echo 'ADB WiFi enabled on port 5555'",
                "ip addr show wlan0 | grep 'inet ' | awk '{print \"Connect: adb connect \" \$2}' | cut -d/ -f1"
            )
        ),
        Script(
            id = "fire_enable_pip_all",
            name = "PiP for All Apps",
            description = "Enables Picture-in-Picture mode for apps that don't normally support it. Watch videos in a small floating window while browsing other apps. Not all apps will work, but many streaming apps benefit from this.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global enable_pip_on_flag_change 1 2>/dev/null || true",
                "settings put global pip_enabled 1 2>/dev/null || true",
                "settings put secure pip_enabled_for_all 1 2>/dev/null || true",
                "echo 'PiP enabled for all apps'"
            )
        ),
        Script(
            id = "fire_enable_freeform",
            name = "Enable Freeform Windows",
            description = "Unlocks hidden windowed/freeform mode allowing apps to run in resizable windows. Advanced feature that enables multitasking with multiple apps visible simultaneously. Requires launcher support to fully utilize.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global enable_freeform_support 1",
                "settings put global force_resizable_activities 1 2>/dev/null || true",
                "echo 'Freeform windows enabled - reboot may be required'"
            )
        ),
        Script(
            id = "fire_unlock_labs",
            name = "Unlock Labs Settings",
            description = "Attempts to enable hidden experimental features and Labs menu in Settings. These features vary by Fire OS version and may include beta UI options, performance tweaks, and unreleased functionality.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put secure settings_labs 1 2>/dev/null || true",
                "settings put global settings_enable_labs 1 2>/dev/null || true",
                "settings put system enable_experimental_features 1 2>/dev/null || true",
                "echo 'Labs settings unlocked'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV SPECIFIC - DISPLAY
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_force_4k",
            name = "Force 4K Output",
            description = "Forces Fire TV to output at 4K (3840x2160) resolution regardless of automatic detection. Use if your 4K TV isn't being recognized properly. Requires HDMI 2.0 cable and 4K-capable Fire TV device (not Fire TV Stick Lite).",
            category = Category.DISPLAY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "wm size 3840x2160 2>/dev/null || true",
                "settings put global display_size_forced 3840x2160 2>/dev/null || true",
                "settings put global user_preferred_resolution 2160 2>/dev/null || true",
                "echo 'Display set to 4K - HDMI cable must support 4K'"
            )
        ),
        Script(
            id = "fire_disable_hdcp",
            name = "Disable HDCP",
            description = "Disables HDCP (High-bandwidth Digital Content Protection) handshake. Can fix 'HDCP Unauthorized' errors, black screens on some TVs, or issues with AV receivers and capture cards. Some streaming services may stop working.",
            category = Category.DISPLAY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global hdcp_checking never 2>/dev/null || true",
                "setprop persist.vendor.disable_hdcp true 2>/dev/null || true",
                "setprop drm.service.enabled false 2>/dev/null || true",
                "echo 'HDCP disabled - may require reboot'"
            )
        ),
        Script(
            id = "fire_reset_display",
            name = "Reset Display Settings",
            description = "Restores all display settings to factory defaults. Fixes resolution issues, overscan problems, or display glitches caused by manual tweaking. Resets resolution, density, and HDCP settings.",
            category = Category.DISPLAY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "wm size reset",
                "wm density reset",
                "settings delete global display_size_forced 2>/dev/null || true",
                "settings delete global user_preferred_resolution 2>/dev/null || true",
                "settings put global hdcp_checking default 2>/dev/null || true",
                "echo 'Display settings reset to default'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV SPECIFIC - DIAGNOSTICS
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_system_info",
            name = "Fire TV System Info",
            description = "Displays complete system information including model name, Fire OS version, Android version, available RAM, storage space, and network IP address. Essential for troubleshooting and checking device specifications.",
            category = Category.DIAGNOSTICS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "echo '=== Fire TV Device ==='",
                "echo \"Model: \$(getprop ro.product.model)\"",
                "echo \"Name: \$(getprop ro.product.device)\"",
                "echo \"FireOS: \$(getprop ro.build.version.fireos)\"",
                "echo \"Android: \$(getprop ro.build.version.release)\"",
                "echo \"Build: \$(getprop ro.build.display.id)\"",
                "echo ''",
                "echo '=== Memory ==='",
                "cat /proc/meminfo | grep -E 'MemTotal|MemFree|MemAvailable'",
                "echo ''",
                "echo '=== Storage ==='",
                "df -h /data | tail -1",
                "echo ''",
                "echo '=== Network ==='",
                "ip addr show wlan0 2>/dev/null | grep 'inet ' || echo 'WiFi not connected'"
            )
        ),
        Script(
            id = "fire_network_diag",
            name = "Network Diagnostics",
            description = "Complete network diagnostic report showing WiFi signal strength (RSSI), connection speed, IP address, gateway, DNS servers, and internet connectivity test. Use to troubleshoot buffering, slow streaming, or connection drops.",
            category = Category.DIAGNOSTICS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "echo '=== WiFi Status ==='",
                "dumpsys wifi | grep -E 'mWifiInfo|SSID|RSSI|Link|Frequency' | head -10",
                "echo ''",
                "echo '=== IP Configuration ==='",
                "ip addr show wlan0 | grep -E 'inet |state'",
                "ip route | grep default",
                "echo ''",
                "echo '=== DNS Servers ==='",
                "getprop net.dns1",
                "getprop net.dns2",
                "echo ''",
                "echo '=== Connectivity Test ==='",
                "ping -c 1 -W 2 8.8.8.8 && echo 'Internet: OK' || echo 'Internet: FAILED'"
            )
        ),
        Script(
            id = "fire_hardware_test",
            name = "Open Hardware Test",
            description = "Launches Fire TV's built-in hardware diagnostics screen showing device specs, serial number, and system information. Navigate through the menu to test individual components.",
            category = Category.DIAGNOSTICS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -n com.amazon.tv.settings/.tv.device.SystemInfoActivity 2>/dev/null || " +
                "am start -a android.settings.DEVICE_INFO_SETTINGS 2>/dev/null || " +
                "am start -a android.settings.SETTINGS",
                "echo 'Hardware test activity launched'"
            )
        ),
        Script(
            id = "fire_remote_test",
            name = "Open Remote Test",
            description = "Enables visual feedback for every button press on your Fire TV remote. Displays crosshairs and coordinates to verify all buttons are working. Great for diagnosing remote issues or testing third-party remotes.",
            category = Category.DIAGNOSTICS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put system show_touches 1",
                "settings put system pointer_location 1",
                "echo 'Remote test mode enabled - touch/press indicators active'",
                "echo 'Run again or use hide_touches to disable'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV SPECIFIC - PRIVACY
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_disable_data_collection",
            name = "Disable Data Collection",
            description = "Stops Amazon from tracking your app usage, viewing habits, and device behavior. Disables the Device Platform Logger and usage statistics. Reduces background network activity and improves privacy.",
            category = Category.PRIVACY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put secure usage_stats_user_enabled 0 2>/dev/null || true",
                "settings put global device_provisioned_data_collection 0 2>/dev/null || true",
                "settings put secure send_action_app_error 0 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.dp.logger 2>/dev/null || true",
                "echo 'Data collection disabled'"
            )
        ),
        Script(
            id = "fire_clear_watch_history",
            name = "Clear Watch History",
            description = "Wipes your Prime Video watch history, Continue Watching list, and cached data. Useful before lending your Fire TV to someone or resetting recommendations. You'll need to sign in again to Prime Video.",
            category = Category.PRIVACY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm clear com.amazon.avod 2>/dev/null || true",
                "rm -rf /data/data/com.amazon.avod/cache/* 2>/dev/null || true",
                "rm -rf /sdcard/Android/data/com.amazon.avod/cache/* 2>/dev/null || true",
                "echo 'Watch history cleared'"
            )
        ),
        Script(
            id = "fire_disable_personalized_ads",
            name = "Disable Personalized Ads",
            description = "Opts out of Amazon's interest-based advertising system. Ads will still appear but won't be tailored to your viewing habits. Reduces tracking and makes your ad profile less detailed.",
            category = Category.PRIVACY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put secure limit_ad_tracking 1 2>/dev/null || true",
                "settings put global interest_based_ads_enabled 0 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.advertisingidsettings 2>/dev/null || true",
                "echo 'Personalized ads disabled'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV SPECIFIC - POWER / CEC
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_disable_auto_sleep",
            name = "Disable Auto Sleep",
            description = "Keeps your Fire TV awake indefinitely. Perfect for digital signage, ambient displays, or preventing the device from sleeping during long downloads. Note: May increase power consumption.",
            category = Category.PERFORMANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put system screen_off_timeout 2147483647",
                "settings put secure sleep_timeout -1 2>/dev/null || true",
                "svc power stayon true 2>/dev/null || true",
                "echo 'Auto sleep disabled - device stays awake'"
            )
        ),
        Script(
            id = "fire_disable_cec",
            name = "Disable HDMI-CEC",
            description = "Stops your TV from controlling Fire TV via HDMI-CEC. Prevents TV from turning on/off Fire TV, changing inputs automatically, or passing volume commands. Useful if CEC causes conflicts with other devices.",
            category = Category.DISPLAY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global hdmi_cec_enabled 0 2>/dev/null || true",
                "settings put global hdmi_control_enabled 0 2>/dev/null || true",
                "echo 'HDMI-CEC disabled'"
            )
        ),
        Script(
            id = "fire_enable_cec",
            name = "Enable HDMI-CEC",
            description = "Enables HDMI-CEC allowing your TV remote to control Fire TV and vice versa. Turning on Fire TV can turn on your TV, and your TV remote's navigation buttons can control Fire TV. Convenient one-remote setup.",
            category = Category.DISPLAY,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put global hdmi_cec_enabled 1 2>/dev/null || true",
                "settings put global hdmi_control_enabled 1 2>/dev/null || true",
                "echo 'HDMI-CEC enabled'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV SPECIFIC - UPDATES
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_block_updates",
            name = "Block OTA Updates",
            description = "Prevents Fire OS from downloading and installing automatic updates. Useful if you want to stay on a specific version, avoid updates that break sideloaded apps, or prevent bandwidth usage. Can be reversed anytime.",
            category = Category.MAINTENANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm disable-user --user 0 com.amazon.device.software.ota 2>/dev/null || true",
                "pm disable-user --user 0 com.amazon.device.software.ota.override 2>/dev/null || true",
                "settings put global ota_disable_automatic_update 1 2>/dev/null || true",
                "echo 'OTA updates blocked'"
            )
        ),
        Script(
            id = "fire_allow_updates",
            name = "Allow OTA Updates",
            description = "Re-enables automatic Fire OS updates. Your device will check for and install the latest Fire OS version. Recommended for security patches unless you have specific reasons to stay on an older version.",
            category = Category.MAINTENANCE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm enable com.amazon.device.software.ota 2>/dev/null || true",
                "pm enable com.amazon.device.software.ota.override 2>/dev/null || true",
                "settings put global ota_disable_automatic_update 0 2>/dev/null || true",
                "echo 'OTA updates allowed'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV SPECIFIC - HIDDEN MENUS
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_secret_menu",
            name = "Open Secret Menu",
            description = "Launches Amazon's hidden service menu showing detailed device information, factory test options, and diagnostic data not normally accessible. Availability varies by Fire TV model and OS version.",
            category = Category.DEVELOPER,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -n com.amazon.tv.settings/.tv.device.DeviceInfoActivity 2>/dev/null || " +
                "am start -n com.amazon.tv.settings/.SystemInfoActivity 2>/dev/null || " +
                "am start -a android.settings.DEVICE_INFO_SETTINGS",
                "echo 'Secret menu launched (if available)'"
            )
        ),
        Script(
            id = "fire_network_menu",
            name = "Open Network Settings",
            description = "Jumps directly to Fire TV's WiFi and network settings. Faster than navigating through the main settings menu. Useful for quickly switching networks or checking connection details.",
            category = Category.NETWORK,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -n com.amazon.tv.settings/.tv.network.NetworkActivity 2>/dev/null || " +
                "am start -a android.settings.WIFI_SETTINGS",
                "echo 'Network settings opened'"
            )
        ),
        Script(
            id = "fire_apps_menu",
            name = "Open Apps Settings",
            description = "Opens the app management screen where you can view installed apps, check storage usage, force stop apps, clear data/cache, and uninstall sideloaded applications.",
            category = Category.APPS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "am start -n com.amazon.tv.settings/.tv.applications.ManageApplicationsActivity 2>/dev/null || " +
                "am start -a android.settings.APPLICATION_SETTINGS",
                "echo 'Apps settings opened'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV SPECIFIC - CACHE / STORAGE
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_clear_all_cache",
            name = "Clear All Fire TV Cache",
            description = "Mass cache cleanup for every installed app. Frees storage space on Fire TV devices with limited internal memory. Does not delete app data or logins - only temporary cache files. May take a minute to complete.",
            category = Category.CACHE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm list packages | cut -d: -f2 | while read pkg; do pm clear --cache-only \$pkg 2>/dev/null; done",
                "rm -rf /data/system/dropbox/* 2>/dev/null || true",
                "echo 'All app caches cleared'"
            )
        ),
        Script(
            id = "fire_clear_prime_cache",
            name = "Clear Prime Video Cache",
            description = "Clears Prime Video's cached thumbnails, video previews, and temporary download data. Fixes playback issues, loading problems, or 'Can't play title' errors. Does not affect your downloads or watch history.",
            category = Category.CACHE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm clear --cache-only com.amazon.avod 2>/dev/null || true",
                "rm -rf /sdcard/Android/data/com.amazon.avod/cache/* 2>/dev/null || true",
                "rm -rf /data/data/com.amazon.avod/cache/* 2>/dev/null || true",
                "echo 'Prime Video cache cleared'"
            )
        ),
        Script(
            id = "fire_clear_netflix_cache",
            name = "Clear Netflix Cache",
            description = "Removes Netflix cached data including thumbnails and temporary files. Can fix app crashes, loading issues, or error codes. Offline downloads will need to be re-downloaded. Does not sign you out.",
            category = Category.CACHE,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "pm clear --cache-only com.netflix.mediaclient 2>/dev/null || true",
                "rm -rf /sdcard/Android/data/com.netflix.mediaclient/cache/* 2>/dev/null || true",
                "echo 'Netflix cache cleared'"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV SPECIFIC - SIDELOADING / APPS
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_enable_unknown_sources",
            name = "Enable Unknown Sources",
            description = "Allows installation of apps from outside the Amazon App Store. Required for sideloading apps like Kodi, Smart YouTube TV, or custom APKs. Essential first step for expanding your Fire TV's capabilities.",
            category = Category.APPS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put secure install_non_market_apps 1",
                "settings put global verifier_verify_adb_installs 0 2>/dev/null || true",
                "echo 'Unknown sources enabled - sideloading allowed'"
            )
        ),
        Script(
            id = "fire_disable_unknown_sources",
            name = "Disable Unknown Sources",
            description = "Blocks installation of apps from unknown sources. Provides security by preventing accidental installation of malicious APKs. Re-enable anytime you need to sideload a new app.",
            category = Category.APPS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "settings put secure install_non_market_apps 0",
                "echo 'Unknown sources disabled'"
            )
        ),
        Script(
            id = "fire_list_sideloaded",
            name = "List Sideloaded Apps",
            description = "Shows all third-party apps installed outside the Amazon App Store. Useful for tracking what you've sideloaded, troubleshooting, or checking for apps that need updates manually.",
            category = Category.APPS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "echo '=== Sideloaded Apps ==='",
                "pm list packages -3 | cut -d: -f2 | grep -v 'com.amazon' | sort"
            )
        ),

        // ═══════════════════════════════════════════════════════════════
        // FIRE TV SPECIFIC - QUICK ACTIONS
        // ═══════════════════════════════════════════════════════════════
        Script(
            id = "fire_reboot",
            name = "Reboot Fire TV",
            description = "⚠️ Immediately restarts your Fire TV device. Use when the system is unresponsive, after applying major changes, or to fix software glitches. Your streaming will be interrupted.",
            category = Category.QUICK_ACTIONS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            dangerous = true,
            commands = listOf(
                "reboot"
            )
        ),
        Script(
            id = "fire_sleep",
            name = "Sleep Fire TV",
            description = "Puts Fire TV into low-power sleep mode as if you pressed the remote's power button. Device remains connected to WiFi for wake-on-LAN. Saves power while keeping the device ready for quick wake-up.",
            category = Category.QUICK_ACTIONS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "input keyevent KEYCODE_SLEEP",
                "echo 'Fire TV sleeping'"
            )
        ),
        Script(
            id = "fire_wake",
            name = "Wake Fire TV",
            description = "Wakes Fire TV from sleep mode remotely. Useful when controlling Fire TV over ADB/network when you can't access the physical remote. Simulates pressing any button on the remote.",
            category = Category.QUICK_ACTIONS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "input keyevent KEYCODE_WAKEUP",
                "echo 'Fire TV awake'"
            )
        ),
        Script(
            id = "fire_home",
            name = "Go Home",
            description = "Returns to the Fire TV home screen from any app. Equivalent to pressing the Home button on your remote. Useful for remote control via ADB or when an app is stuck.",
            category = Category.QUICK_ACTIONS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "input keyevent KEYCODE_HOME",
                "echo 'Home screen'"
            )
        ),
        Script(
            id = "fire_voice_search",
            name = "Trigger Voice Search",
            description = "Opens the voice search interface as if you pressed the microphone button on your remote. Launches Alexa voice input (if enabled) or the standard Fire TV search. Requires Alexa to be enabled for voice commands.",
            category = Category.QUICK_ACTIONS,
            deviceTypes = setOf(DeviceType.FIRE_TV),
            commands = listOf(
                "input keyevent KEYCODE_SEARCH",
                "echo 'Voice search triggered'"
            )
        )
    )

    fun getById(id: String): Script? = all.find { it.id == id }

    fun getByCategory(category: Category): List<Script> = all.filter { it.category == category }
}
