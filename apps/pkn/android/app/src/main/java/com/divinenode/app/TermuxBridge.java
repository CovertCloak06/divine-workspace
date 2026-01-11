package com.divinenode.app;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "TermuxBridge")
public class TermuxBridge extends Plugin {

    private static final String TAG = "TermuxBridge";

    @PluginMethod
    public void startBackend(PluginCall call) {
        try {
            Context context = getContext();

            // Create intent to run Termux command
            Intent intent = new Intent();
            intent.setClassName("com.termux", "com.termux.app.RunCommandService");
            intent.setAction("com.termux.RUN_COMMAND");

            // Set command path
            String scriptPath = "/data/data/com.termux/files/home/pkn/termux_start.sh";
            intent.putExtra("com.termux.RUN_COMMAND_PATH", scriptPath);
            intent.putExtra("com.termux.RUN_COMMAND_WORKDIR", "/data/data/com.termux/files/home/pkn");
            intent.putExtra("com.termux.RUN_COMMAND_BACKGROUND", true);

            Log.d(TAG, "Starting Termux backend: " + scriptPath);

            // Start the service
            context.startService(intent);

            JSObject ret = new JSObject();
            ret.put("success", true);
            ret.put("message", "Termux backend start command sent");
            call.resolve(ret);

        } catch (Exception e) {
            Log.e(TAG, "Failed to start Termux backend", e);
            call.reject("Failed to start backend: " + e.getMessage());
        }
    }

    @PluginMethod
    public void checkTermuxInstalled(PluginCall call) {
        try {
            Context context = getContext();
            boolean installed = isPackageInstalled(context, "com.termux");

            JSObject ret = new JSObject();
            ret.put("installed", installed);
            call.resolve(ret);

        } catch (Exception e) {
            call.reject("Failed to check Termux installation: " + e.getMessage());
        }
    }

    private boolean isPackageInstalled(Context context, String packageName) {
        try {
            context.getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
