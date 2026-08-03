# WoS Font Calibration Kit

Measures the **real character widths of Whiteout Survival's chat font** from
screenshots, so the Frostline editor + gallery preview can use the game's own
metrics. WoS's font is sealed inside the game (encrypted Unity bundles), so
measuring its rendering is the only way to mirror it — and because WoS bakes
the font into the app, one phone's measurements are valid for every player.

## How it works

Each `strings/cNN.txt` is one chat message full of "rulers": a run of N
copies of a character, then the same run at 2N, each ending in a `█` marker.

    advance = (ink_width(2N) − ink_width(N)) / N

The subtraction cancels the marker width and all side bearings, so the
result is the character's true advance — no guessing, no font internals.
Invisible characters (spaces) are bracketed `█····█` instead.

33 characters are calibrated: blocks (█▂▔▕▏), spaces (regular, NBSP,
ideographic, em), box drawing (─━═║┃│┏╭╲), kaomoji staples (ノ⊂∧ωニ),
fullwidth forms (（｜・＊), and narrow chars (i m ( | . ﾉ) — chosen from
what the library's 236 pieces actually use.

The whole pipeline is self-tested: rendering these strings with Frostline's
own font (whose widths are known exactly) and measuring the screenshots
recovers all 33 values within 0.02em.

## Run it (Termux on the phone, ~10 minutes)

    pkg install android-tools termux-api        # + Termux:API app
    # Developer options -> Wireless debugging -> Pair device with code
    adb pair localhost:PAIR_PORT
    adb connect localhost:CONNECT_PORT
    bash run.sh

`run.sh` puts each message on the clipboard; you paste + send it in any WoS
chat and press Enter — it screenshots via adb into `shots/`. Alliance or
personal chat both work (personal is quieter). It's just pasting and
screenshotting — nothing touches the game itself.

Then either send `shots/` back to Claude, or measure on-device:

    pkg install python python-pillow
    python measure.py shots/            # writes wos-metrics.json

## What happens with the numbers

`wos-metrics.json` holds each character's advance relative to `█`. Those
ratios get baked into `assets/frostline-art.woff2` so editor and preview
lay text out exactly the way WoS does. Art files are never touched — this
only changes how the preview font measures.

## Capture tips

- The **whole message bubble** must be visible when you press Enter
  (scroll so nothing is cut off; the newest/bottom bubble is measured).
- Don't pinch-zoom the chat.
- If `measure.py` flags a message, just delete that `shots/cNN.png` and
  re-run `run.sh` — it skips ones already captured.

## Fidelity notes discovered while building this

- Browser default `text-spacing-trim` halves runs of fullwidth punctuation
  (（（ etc.) — TextMeshPro (WoS) doesn't. The preview/editor CSS needs
  `text-spacing-trim: space-all` (+ `font-kerning: none`) to match the game.
- Noto CJK draws block glyphs taller than the line box; rulers here are
  separated by blank lines so screenshot measurement stays unambiguous.
