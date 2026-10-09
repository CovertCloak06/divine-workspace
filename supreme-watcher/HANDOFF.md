# Setting up Supreme Watcher (for the person running it)

This guide gets the watcher running on **an old Android phone** or a **Raspberry
Pi** at home. Once it's set up, it runs 24/7 and restarts itself — you shouldn't
need to touch it.

> **Why it runs at home:** Supreme blocks requests from cloud/datacenter servers.
> A phone or Pi on your **home Wi-Fi** looks like a normal person, so it works —
> and it's free (no hosting bill). The only cost is Pushover (~$5 one time).

---

## First: get Pushover on your iPhone (~3 min)

1. Install **Pushover** from the App Store and create an account.
2. On the app's home screen, copy **Your User Key**.
3. In a browser go to **pushover.net** → log in → **Create an Application/API
   Token** → name it "Supreme Watcher" → copy the **API Token**.

Keep those two codes handy for the setup page below.

---

## Option A — Old Android phone (recommended, free)

You'll need the phone plugged into a charger and on Wi-Fi. Two free apps from
**F-Droid** (not the Play Store): **Termux** and **Termux:Boot**.

1. Install **Termux** and **Termux:Boot** from F-Droid. Open **Termux:Boot** once
   (just opening it is enough — it grants run-on-boot).
2. In **Termux**, paste this one line and press enter:
   ```bash
   pkg install -y curl && curl -sL https://raw.githubusercontent.com/CovertCloak06/supreme-watcher/main/scripts/install.sh | bash
   ```
3. When it says *"Open http://localhost:8787"*, open that address in the phone's
   browser. A setup page appears:
   - Paste your **User Key** and **API Token**.
   - (Optional) add keywords like `box logo, tee` and a max price.
   - Tap **Test** — your phone should buzz with a test notification.
   - Tap **Save & Start**.
4. Back in Termux it finishes and starts watching. Done.

**One-time phone permissions to grant (so it never stops):**
- Settings → Apps → **Termux** → Battery → **Unrestricted** (disable battery
  optimization).
- Same for **Termux:Boot**.
- Keep the phone plugged in.

Logs (if you're curious): in Termux, `cat ~/supreme-watcher.log`.

---

## Option B — Raspberry Pi (free after the ~$50–80 board)

1. Flash **Raspberry Pi OS Lite** with the Raspberry Pi Imager. In the Imager's
   settings (gear icon) pre-set **your Wi-Fi** and **enable SSH** — then it comes
   online by itself.
2. SSH in (or open a terminal) and paste:
   ```bash
   curl -sL https://raw.githubusercontent.com/CovertCloak06/supreme-watcher/main/scripts/install.sh | bash
   ```
3. When the setup page URL appears, open `http://<the-pi's-ip>:8787` from any
   device on the same Wi-Fi, fill in your Pushover keys, **Test**, **Save & Start**.
4. It installs as a system service that auto-starts on boot and restarts on crash.

Check it: `sudo systemctl status supreme-watcher` · Logs: `sudo journalctl -u supreme-watcher -f`

---

## Pre-baked Pi (the "just plug it in" version)

If whoever built this sets up the Pi for you first, they can bake in your Wi-Fi
and Pushover keys ahead of time. Then you literally **plug it in at home and it
starts working** — no setup page, no typing. Ask them for that if you'd prefer it.

---

## If something looks wrong

| Symptom | Fix |
|---|---|
| No notifications ever | Re-run setup, tap **Test** — if the test doesn't arrive, the Pushover keys are wrong. |
| Worked, then stopped (Android) | Make sure battery optimization is **off** for Termux + Termux:Boot, and the phone is charged/on Wi-Fi. |
| `HTTP 403` in the logs | The device isn't on a home connection. Move it to home Wi-Fi. |

To reconfigure later (new keys/filters), the watcher must be **restarted** to pick
up the changes — writing `.env` alone isn't enough:
- **Android (Termux):** `cd ~/supreme-watcher && npm run setup`, save in the page,
  then `pkill -f dist/index.js` (Termux:Boot relaunches it with the new settings) —
  or just reboot the phone.
- **Raspberry Pi:** `cd ~/supreme-watcher && npm run setup`, save, then
  `sudo systemctl restart supreme-watcher`.
