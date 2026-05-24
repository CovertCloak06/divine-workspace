// Frostline art library.
//
// CHARACTER FAMILIES — pick ONE per piece for best alignment in proportional fonts:
//   1. Block elements: █ ▓ ▒ ░  +  box-drawing: ─ │ ┌ ┐ └ ┘ ╔ ╗ ╚ ╝ ═ ║
//      Use ' ' (regular space) or ░ as background. Renders well in monospace,
//      mostly aligned in proportional fonts.
//   2. Pure emoji rows. Each row is N emoji wide. Most consistent in proportional
//      fonts. Don't mix emoji with non-emoji glyphs in the same row.
//   3. Single-line decorative: ✦ ━━━ ✦ etc. — very forgiving, always works.
//
// To add your own: copy the shape of an existing entry. Tags: love, nature,
// banners, decorative, animals, borders, celebration, symbols.

const ART = [
  // ─────────────────────────── LOVE ───────────────────────────
  {
    id: 'heart-small',
    title: 'Heart (small)',
    tags: ['love', 'symbols'],
    width: 7, height: 6,
    wosRisk: true,
    art:
` ██ ██
███████
███████
 █████
  ███
   █   `
  },
  {
    id: 'heart-bold',
    title: 'Heart (bold)',
    tags: ['love'],
    width: 11, height: 9,
    wosRisk: true,
    art:
` ███ ███
█████████
███████████
███████████
███████████
 █████████
  ███████
   █████
     █     `
  },
  {
    id: 'heart-row',
    title: 'Heart Row',
    tags: ['love', 'decorative'],
    width: 5, height: 1,
    art: '❤️💛💚💙💜'
  },
  {
    id: 'love-banner',
    title: 'Love Banner',
    tags: ['love', 'banners'],
    width: 13, height: 3,
    art:
`✦━━━━━━━━━━━✦
━ ♥ LOVE ♥ ━
✦━━━━━━━━━━━✦`
  },
  {
    id: 'cupids-arrow',
    title: 'Cupid Arrow',
    tags: ['love', 'symbols'],
    width: 11, height: 1,
    art: '♥ ❤️ ❤️ ❤️ ♥'
  },

  // ────────────────────────── NATURE ──────────────────────────
  {
    id: 'snowflake-block',
    title: 'Snowflake',
    tags: ['nature', 'symbols'],
    width: 9, height: 9,
    wosRisk: true,
    art:
`    █
 █  █  █
  █ █ █
   ███
█████████
   ███
  █ █ █
 █  █  █
    █    `
  },
  {
    id: 'snowflake-emoji',
    title: 'Snowflake (emoji)',
    tags: ['nature', 'decorative'],
    width: 5, height: 3,
    art:
`❄️✨❄️✨❄️
✨❄️★❄️✨
❄️✨❄️✨❄️`
  },
  {
    id: 'snow-row',
    title: 'Snow Row',
    tags: ['nature', 'decorative'],
    width: 7, height: 1,
    art: '❄️❄️❄️⛄❄️❄️❄️'
  },
  {
    id: 'pine-tree',
    title: 'Pine Tree',
    tags: ['nature'],
    width: 11, height: 9,
    wosRisk: true,
    art:
`     █
    ███
   █████
  ███████
 █████████
███████████
    ███
    ███
    ███    `
  },
  {
    id: 'mountain',
    title: 'Mountain',
    tags: ['nature'],
    width: 15, height: 6,
    wosRisk: true,
    art:
`       █
      ███
     █████
    ███████
   █████████
  ███████████  `
  },
  {
    id: 'flower-row',
    title: 'Flower Row',
    tags: ['nature', 'decorative'],
    width: 5, height: 1,
    art: '🌸🌺🌻🌷🌹'
  },

  // ────────────────────────── ANIMALS ──────────────────────────
  {
    id: 'dragon-emoji',
    title: 'Dragon',
    tags: ['animals'],
    width: 3, height: 3,
    art:
`🔥⚡🔥
⚡💀⚡
🔥⚡🔥`
  },
  {
    id: 'animal-row',
    title: 'Animal Row',
    tags: ['animals', 'decorative'],
    width: 7, height: 1,
    art: '🐻🦊🐺🦁🐯🐼🐧'
  },
  {
    id: 'butterfly',
    title: 'Butterfly',
    tags: ['animals', 'nature'],
    width: 7, height: 1,
    art: '🦋🌸🦋🌸🦋🌸🦋'
  },

  // ────────────────────────── BANNERS ──────────────────────────
  {
    id: 'welcome-banner',
    title: 'Welcome Banner',
    tags: ['banners', 'celebration'],
    width: 17, height: 3,
    wosRisk: true,
    art:
`╔═══════════════╗
║   WELCOME!    ║
╚═══════════════╝`
  },
  {
    id: 'congrats-banner',
    title: 'Congrats',
    tags: ['banners', 'celebration'],
    width: 15, height: 1,
    art: '🎉━━ CONGRATS ━━🎉'
  },
  {
    id: 'alliance-banner',
    title: 'Alliance Recruiting',
    tags: ['banners'],
    width: 24, height: 3,
    art:
`⚡═══════════════════⚡
══ ALLIANCE RECRUITING
⚡═══════════════════⚡`
  },
  {
    id: 'birthday-banner',
    title: 'Happy Birthday',
    tags: ['banners', 'celebration'],
    width: 22, height: 3,
    art:
`🎂✦━━━━━━━━━━━━━━━━━━✦🎂
━ HAPPY BIRTHDAY ━
🎂✦━━━━━━━━━━━━━━━━━━✦🎂`
  },

  // ───────────────────── DECORATIVE / BORDERS ─────────────────────
  {
    id: 'star-divider',
    title: 'Star Divider',
    tags: ['borders', 'decorative'],
    width: 13, height: 1,
    art: '✦ ━━━━━━━━━ ✦'
  },
  {
    id: 'wave-divider',
    title: 'Wave Divider',
    tags: ['borders', 'decorative'],
    width: 13, height: 1,
    art: '～～～～～～～～～～～～～'
  },
  {
    id: 'diamond-divider',
    title: 'Diamond Divider',
    tags: ['borders', 'decorative'],
    width: 13, height: 1,
    wosRisk: true,
    art: '◆━━━━━━━━━━━◆'
  },
  {
    id: 'frame-simple',
    title: 'Simple Frame',
    tags: ['borders'],
    width: 13, height: 3,
    wosRisk: true,
    art:
`┌───────────┐
│           │
└───────────┘`
  },
  {
    id: 'frame-double',
    title: 'Double Frame',
    tags: ['borders'],
    width: 13, height: 4,
    wosRisk: true,
    art:
`╔═══════════╗
║           ║
║           ║
╚═══════════╝`
  },
  {
    id: 'frame-fancy',
    title: 'Fancy Frame',
    tags: ['borders', 'decorative'],
    width: 17, height: 5,
    wosRisk: true,
    art:
`✦━━━━━━━━━━━━━━━✦
┃               ┃
┃               ┃
┃               ┃
✦━━━━━━━━━━━━━━━✦`
  },

  // ────────────────────── CELEBRATION ──────────────────────
  {
    id: 'star-burst',
    title: 'Star Burst',
    tags: ['celebration', 'symbols'],
    width: 5, height: 1,
    art: '✨⭐🌟⭐✨'
  },
  {
    id: 'fireworks',
    title: 'Fireworks',
    tags: ['celebration'],
    width: 5, height: 1,
    art: '🎆✨🎇✨🎆'
  },
  {
    id: 'party',
    title: 'Party Row',
    tags: ['celebration'],
    width: 5, height: 1,
    art: '🎉🥳🎊🥂🎉'
  },
  {
    id: 'crown',
    title: 'Crown',
    tags: ['symbols', 'celebration'],
    width: 7, height: 4,
    wosRisk: true,
    art:
`█ █ █ █
███████
███████
███████`
  },

  // ────────────────────────── SYMBOLS ──────────────────────────
  {
    id: 'sword-shield',
    title: 'Sword & Shield',
    tags: ['symbols'],
    width: 3, height: 1,
    art: '⚔️🛡️⚔️'
  },
  {
    id: 'arrows-rain',
    title: 'Arrows',
    tags: ['symbols', 'decorative'],
    width: 7, height: 1,
    art: '▶▶▶▶▶▶▶'
  },
  {
    id: 'sparkle-line',
    title: 'Sparkle Line',
    tags: ['decorative', 'symbols'],
    width: 9, height: 1,
    art: '· ✦ ✧ ✦ ✧ ✦ ✧ ✦ ·'
  },

  // ────────────────────── AESTHETIC DIVIDERS ──────────────────────
  {
    id: 'aes-flowers',
    title: 'Flower Divider',
    tags: ['aesthetic', 'borders', 'decorative'],
    width: 17, height: 1,
    art: '╭┈ • ┈ ୨୧ ┈ • ┈╮'
  },
  {
    id: 'aes-moon-stars',
    title: 'Moon & Stars',
    tags: ['aesthetic', 'decorative'],
    width: 15, height: 1,
    art: '⋆ ˚｡⋆୨୧˚ ˚୨୧⋆｡˚ ⋆'
  },
  {
    id: 'aes-sparkle-frame',
    title: 'Sparkle Frame',
    tags: ['aesthetic', 'borders'],
    width: 20, height: 1,
    art: '₊˚ ✧ ━━━━⊱⋆⊰━━━━ ✧˚₊'
  },
  {
    id: 'aes-double-frame',
    title: 'Ornate Frame',
    tags: ['aesthetic', 'borders'],
    width: 19, height: 1,
    wosRisk: true,
    art: '╔═.·:·.✧ ✦ ✧.·:·.═╗'
  },
  {
    id: 'aes-heart-frame',
    title: 'Heart Brackets',
    tags: ['aesthetic', 'love', 'borders'],
    width: 11, height: 1,
    art: '⏔ ꒰ ♡ ꒱ ⏔'
  },
  {
    id: 'aes-tiny-flowers',
    title: 'Tiny Flowers',
    tags: ['aesthetic', 'minimalist'],
    width: 12, height: 1,
    wosRisk: true,
    art: '𓇢𓆸 ⋆｡˚ 𓇢𓆸'
  },
  {
    id: 'aes-celestial',
    title: 'Celestial',
    tags: ['aesthetic', 'decorative'],
    width: 14, height: 1,
    art: '✩₊˚.⋆☾⋆⁺₊✧'
  },
  {
    id: 'aes-soft-line',
    title: 'Soft Line',
    tags: ['aesthetic', 'minimalist', 'borders'],
    width: 13, height: 1,
    art: '°˖✧◝(⁰▿⁰)◜✧˖°'
  },
  {
    id: 'aes-dotted-divider',
    title: 'Dotted Divider',
    tags: ['aesthetic', 'minimalist'],
    width: 11, height: 1,
    art: '· · ─ ♡ ─ · ·'
  },
  {
    id: 'aes-flourish',
    title: 'Flourish',
    tags: ['aesthetic', 'decorative'],
    width: 17, height: 1,
    wosRisk: true,
    art: '⊹ ࣪ ﹏𓊝﹏𓂁﹏⊹ ࣪'
  },

  // ────────────────────────── KAWAII ──────────────────────────
  {
    id: 'kawaii-bear',
    title: 'Bear',
    tags: ['kawaii', 'animals'],
    width: 5, height: 1,
    art: 'ʕ•ᴥ•ʔ'
  },
  {
    id: 'kawaii-happy',
    title: 'Happy Face',
    tags: ['kawaii', 'memes'],
    width: 5, height: 1,
    art: '(◕‿◕)'
  },
  {
    id: 'kawaii-wink',
    title: 'Wink',
    tags: ['kawaii'],
    width: 5, height: 1,
    art: '(>ᴗ•)'
  },
  {
    id: 'kawaii-smile',
    title: 'Closed Eyes Smile',
    tags: ['kawaii'],
    width: 3, height: 1,
    art: '≧◡≦'
  },
  {
    id: 'kawaii-bear-paws',
    title: 'Small Bear',
    tags: ['kawaii', 'animals'],
    width: 8, height: 1,
    art: '(´• ω •`)'
  },
  {
    id: 'kawaii-throw-love',
    title: 'Throwing Love',
    tags: ['kawaii', 'love'],
    width: 11, height: 1,
    art: '(っ◔◡◔)っ ♥'
  },
  {
    id: 'kawaii-sparkle-throw',
    title: 'Sparkle Throw',
    tags: ['kawaii', 'celebration', 'memes'],
    width: 14, height: 1,
    art: '(ノ◕ヮ◕)ノ*:・゚✧'
  },
  {
    id: 'kawaii-cat',
    title: 'Cat',
    tags: ['kawaii', 'animals'],
    width: 6, height: 1,
    art: '(=^･ω･^=)'
  },
  {
    id: 'kawaii-blush',
    title: 'Blush',
    tags: ['kawaii'],
    width: 5, height: 1,
    art: '(◡‿◡✿)'
  },
  {
    id: 'kawaii-flower-girl',
    title: 'Flower Girl',
    tags: ['kawaii'],
    width: 9, height: 1,
    art: '✿◕ ‿ ◕✿'
  },

  // ─────────────────────────── MEMES ───────────────────────────
  {
    id: 'meme-lenny',
    title: 'Lenny Face',
    tags: ['memes'],
    width: 9, height: 1,
    art: '( ͡° ͜ʖ ͡°)'
  },
  {
    id: 'meme-shrug',
    title: 'Shrug',
    tags: ['memes'],
    width: 9, height: 1,
    art: '¯\\_(ツ)_/¯'
  },
  {
    id: 'meme-tableflip',
    title: 'Table Flip',
    tags: ['memes'],
    width: 13, height: 1,
    art: '(╯°□°)╯︵ ┻━┻'
  },
  {
    id: 'meme-tableback',
    title: 'Put Table Back',
    tags: ['memes'],
    width: 12, height: 1,
    art: '┬─┬ノ(ಠ_ಠノ)'
  },
  {
    id: 'meme-disapproval',
    title: 'Disapproval',
    tags: ['memes'],
    width: 7, height: 1,
    art: 'ಠ_ಠ'
  },
  {
    id: 'meme-disappoint',
    title: 'Look of Disappointment',
    tags: ['memes'],
    width: 12, height: 1,
    art: 'ಠ︵ಠ'
  },
  {
    id: 'meme-fingers',
    title: 'This Is Fine Fingers',
    tags: ['memes'],
    width: 6, height: 1,
    art: '☞ ͡° ͜ʖ ͡°)☞'
  },
  {
    id: 'meme-monocle',
    title: 'Monocle',
    tags: ['memes'],
    width: 11, height: 1,
    art: 'ಠ‿ಠ'
  },
  {
    id: 'meme-cry-laugh',
    title: 'Cry Laugh',
    tags: ['memes'],
    width: 9, height: 1,
    art: '(╥﹏╥)'
  },
  {
    id: 'meme-rage',
    title: 'Rage',
    tags: ['memes'],
    width: 9, height: 1,
    art: '(ಠ益ಠ)'
  },
  {
    id: 'meme-music',
    title: 'Dancing',
    tags: ['memes'],
    width: 13, height: 1,
    art: '♪┏(°.°)┛┗(°.°)┓'
  },
  {
    id: 'meme-confused',
    title: 'Confused',
    tags: ['memes'],
    width: 7, height: 1,
    art: '(⊙_⊙)'
  },

  // ────────────────────────── GOTHIC ──────────────────────────
  {
    id: 'gothic-skull',
    title: 'Skull Borders',
    tags: ['gothic'],
    width: 13, height: 1,
    wosRisk: true,
    art: '⋆༺𓆩☠︎︎𓆪༻⋆'
  },
  {
    id: 'gothic-cross',
    title: 'Cross Decoration',
    tags: ['gothic'],
    width: 11, height: 1,
    art: '✟ ─── ✟ ─── ✟'
  },
  {
    id: 'gothic-rose',
    title: 'Black Rose',
    tags: ['gothic'],
    width: 5, height: 1,
    art: '🥀━━🥀'
  },
  {
    id: 'gothic-fang',
    title: 'Fang Bracket',
    tags: ['gothic'],
    width: 11, height: 1,
    wosRisk: true,
    art: '𓆩♱𓆪 ━━ 𓆩♱𓆪'
  },
  {
    id: 'gothic-knight',
    title: 'Dark Knight',
    tags: ['gothic', 'symbols'],
    width: 5, height: 1,
    art: '⚔☠⚔'
  },

  // ────────────────────── SAYINGS / TEXT ──────────────────────
  {
    id: 'saying-gg',
    title: 'GG WP',
    tags: ['sayings', 'celebration'],
    width: 13, height: 1,
    art: '✧ GG WP ✧'
  },
  {
    id: 'saying-good-luck',
    title: 'Good Luck',
    tags: ['sayings'],
    width: 17, height: 1,
    art: '✨ GOOD LUCK ✨'
  },
  {
    id: 'saying-hello',
    title: 'Hello',
    tags: ['sayings'],
    width: 15, height: 1,
    art: '✿ ─ Hello ─ ✿'
  },
  {
    id: 'saying-thanks',
    title: 'Thank You',
    tags: ['sayings'],
    width: 17, height: 1,
    art: '♡ THANK YOU ♡'
  },
  {
    id: 'saying-have-fun',
    title: 'Have Fun',
    tags: ['sayings'],
    width: 13, height: 1,
    art: '🎉 HAVE FUN 🎉'
  },
  {
    id: 'saying-bye',
    title: 'Bye',
    tags: ['sayings'],
    width: 13, height: 1,
    art: '╰ ❀ BYE ❀ ╯'
  },
  {
    id: 'saying-night',
    title: 'Goodnight',
    tags: ['sayings'],
    width: 17, height: 1,
    art: '🌙 GOODNIGHT ✨'
  },
  {
    id: 'saying-morning',
    title: 'Good Morning',
    tags: ['sayings'],
    width: 18, height: 1,
    art: '☀ GOOD MORNING ☀'
  },
  {
    id: 'saying-attack',
    title: 'Attack',
    tags: ['sayings', 'banners'],
    width: 17, height: 1,
    art: '⚔ ━ ATTACK ━ ⚔'
  },
  {
    id: 'saying-defend',
    title: 'Defend',
    tags: ['sayings', 'banners'],
    width: 17, height: 1,
    art: '🛡 ━ DEFEND ━ 🛡'
  },
  {
    id: 'saying-victory',
    title: 'Victory',
    tags: ['sayings', 'celebration'],
    width: 17, height: 1,
    art: '👑 VICTORY 👑'
  },
  {
    id: 'saying-help',
    title: 'Need Help',
    tags: ['sayings'],
    width: 17, height: 1,
    art: '⚠ NEED HELP ⚠'
  },

  // ────────────────────── MINIMALIST ──────────────────────
  {
    id: 'min-dot-line',
    title: 'Dot Line',
    tags: ['minimalist', 'borders'],
    width: 15, height: 1,
    art: '· · · · · · · · · ·'
  },
  {
    id: 'min-em-dash',
    title: 'Em Dash Line',
    tags: ['minimalist', 'borders'],
    width: 11, height: 1,
    art: '─────────────'
  },
  {
    id: 'min-thick-dash',
    title: 'Thick Line',
    tags: ['minimalist', 'borders'],
    width: 13, height: 1,
    art: '━━━━━━━━━━━━━'
  },
  {
    id: 'min-double-dash',
    title: 'Double Line',
    tags: ['minimalist', 'borders'],
    width: 13, height: 1,
    art: '═════════════'
  },
  {
    id: 'min-wave',
    title: 'Wave',
    tags: ['minimalist'],
    width: 7, height: 1,
    art: '∽∽∽∽∽∽∽'
  },
  {
    id: 'min-tilde',
    title: 'Tilde',
    tags: ['minimalist'],
    width: 9, height: 1,
    art: '~~~~~~~~~'
  },
  {
    id: 'min-bullet',
    title: 'Center Bullet',
    tags: ['minimalist'],
    width: 7, height: 1,
    art: '· · · • · · ·'
  },
  {
    id: 'min-three-dots',
    title: 'Three Dots',
    tags: ['minimalist'],
    width: 3, height: 1,
    art: '• • •'
  },
  {
    id: 'min-small-cross',
    title: 'Small Cross',
    tags: ['minimalist'],
    width: 5, height: 1,
    art: '┄┈┄┈┄'
  },

  // ────────────────────── EXTRA EMOJI ROWS ──────────────────────
  {
    id: 'emoji-fire',
    title: 'Fire Trail',
    tags: ['decorative', 'celebration'],
    width: 7, height: 1,
    art: '🔥🔥🔥🔥🔥🔥🔥'
  },
  {
    id: 'emoji-money',
    title: 'Money',
    tags: ['celebration'],
    width: 5, height: 1,
    art: '💰💵💸💵💰'
  },
  {
    id: 'emoji-skull',
    title: 'Skull Row',
    tags: ['gothic'],
    width: 5, height: 1,
    art: '💀☠️💀☠️💀'
  },
  {
    id: 'emoji-music',
    title: 'Music Notes',
    tags: ['decorative'],
    width: 7, height: 1,
    art: '🎵♪♫🎶♪♫🎵'
  },
  {
    id: 'emoji-stars',
    title: 'Star Trail',
    tags: ['decorative', 'celebration'],
    width: 7, height: 1,
    art: '⭐✨⭐✨⭐✨⭐'
  },
  {
    id: 'emoji-coffee',
    title: 'Coffee Break',
    tags: ['decorative'],
    width: 5, height: 1,
    art: '☕📚☕📚☕'
  },
  {
    id: 'emoji-game',
    title: 'Game On',
    tags: ['celebration'],
    width: 5, height: 1,
    art: '🎮⚔️🛡️⚔️🎮'
  },

  // ────────────────────── COMBO FRAMES ──────────────────────
  {
    id: 'combo-name-frame',
    title: 'Name Frame',
    tags: ['banners', 'aesthetic'],
    width: 21, height: 3,
    art:
`✦ ━━━━━━━━━━━━━━━ ✦
━━ ⋆ YOUR NAME ⋆ ━━
✦ ━━━━━━━━━━━━━━━ ✦`
  },
  {
    id: 'combo-quote-frame',
    title: 'Quote Frame',
    tags: ['banners', 'sayings'],
    width: 21, height: 3,
    art:
`╭━━━━━━━━ ♡ ━━━━━━━━╮
━━━━ QUOTE HERE ━━━━
╰━━━━━━━━ ♡ ━━━━━━━━╯`
  },
  {
    id: 'combo-castle-up',
    title: 'Castle Upgrade',
    tags: ['banners', 'celebration'],
    width: 19, height: 1,
    art: '🏰⬆ CASTLE UP! ⬆🏰'
  },

  // ─────────────── WINTER / ICE (Whiteout themed) ───────────────
  {
    id: 'winter-snow-fall',
    title: 'Snow Falling',
    tags: ['nature', 'aesthetic'],
    width: 13, height: 1,
    art: '❄ ⋆ ❄ ⋆ ❄ ⋆ ❄'
  },
  {
    id: 'winter-frost-line',
    title: 'Frost Line',
    tags: ['nature', 'borders'],
    width: 17, height: 1,
    art: '❄━━━━━━❄━━━━━━❄'
  },
  {
    id: 'winter-snowman-row',
    title: 'Snowmen',
    tags: ['nature', 'celebration'],
    width: 5, height: 1,
    art: '⛄❄️⛄❄️⛄'
  },
  {
    id: 'winter-mug',
    title: 'Hot Cocoa',
    tags: ['nature', 'aesthetic'],
    width: 5, height: 1,
    art: '☕ ❄️ ☃️ ❄️ ☕'
  },
  {
    id: 'winter-icicle-frame',
    title: 'Icicle Frame',
    tags: ['nature', 'borders'],
    width: 15, height: 3,
    art:
`❄️═════════════❄️

❄️═════════════❄️`
  },
  {
    id: 'winter-blizzard',
    title: 'Blizzard',
    tags: ['nature'],
    width: 9, height: 1,
    art: '🌨️❄️🌨️❄️🌨️❄️🌨️❄️🌨️'
  },
  {
    id: 'winter-aurora',
    title: 'Aurora',
    tags: ['nature', 'aesthetic'],
    width: 13, height: 1,
    art: '✦ ⋆ ✧ ⋆ ✦ ⋆ ✧ ⋆ ✦'
  },
  {
    id: 'winter-cabin',
    title: 'Winter Cabin',
    tags: ['nature'],
    width: 5, height: 1,
    art: '🏔️🌲🏠🌲🏔️'
  },
  {
    id: 'winter-skater',
    title: 'Skater Row',
    tags: ['nature', 'celebration'],
    width: 5, height: 1,
    art: '⛸️❄️⛸️❄️⛸️'
  },
  {
    id: 'winter-cold-day',
    title: 'Cold Day',
    tags: ['sayings', 'nature'],
    width: 15, height: 1,
    art: '❄️ STAY WARM ❄️'
  },

  // ─────────────────────── HOLIDAYS ───────────────────────
  {
    id: 'holiday-christmas',
    title: 'Christmas',
    tags: ['celebration'],
    width: 5, height: 1,
    art: '🎄🎁🎅🎁🎄'
  },
  {
    id: 'holiday-xmas-banner',
    title: 'Merry Christmas',
    tags: ['celebration', 'banners', 'sayings'],
    width: 21, height: 3,
    art:
`🎄━━━━━━━━━━━━━━━🎄
━ MERRY CHRISTMAS ━
🎄━━━━━━━━━━━━━━━🎄`
  },
  {
    id: 'holiday-halloween',
    title: 'Halloween',
    tags: ['celebration', 'gothic'],
    width: 5, height: 1,
    art: '🎃👻💀👻🎃'
  },
  {
    id: 'holiday-spooky',
    title: 'Spooky Time',
    tags: ['celebration', 'gothic', 'sayings'],
    width: 15, height: 1,
    art: '🦇 BOO! 🦇'
  },
  {
    id: 'holiday-valentine',
    title: 'Valentine Hearts',
    tags: ['celebration', 'love'],
    width: 5, height: 1,
    art: '💘💝💖💝💘'
  },
  {
    id: 'holiday-easter',
    title: 'Easter',
    tags: ['celebration', 'nature'],
    width: 5, height: 1,
    art: '🐰🥚🌷🥚🐰'
  },
  {
    id: 'holiday-nye',
    title: 'New Year',
    tags: ['celebration', 'sayings'],
    width: 17, height: 1,
    art: '🎆 NEW YEAR! 🎆'
  },
  {
    id: 'holiday-thanks',
    title: 'Thanksgiving',
    tags: ['celebration'],
    width: 5, height: 1,
    art: '🦃🍂🌽🍂🦃'
  },
  {
    id: 'holiday-stpat',
    title: 'St. Patricks',
    tags: ['celebration', 'nature'],
    width: 5, height: 1,
    art: '🍀💚🌈💚🍀'
  },

  // ─────────────────────── FOOD ───────────────────────
  {
    id: 'food-pizza',
    title: 'Pizza Time',
    tags: ['decorative', 'sayings'],
    width: 11, height: 1,
    art: '🍕 PIZZA! 🍕'
  },
  {
    id: 'food-cake',
    title: 'Cake',
    tags: ['celebration', 'decorative'],
    width: 5, height: 1,
    art: '🍰🎂🧁🎂🍰'
  },
  {
    id: 'food-coffee-time',
    title: 'Coffee Time',
    tags: ['sayings', 'decorative'],
    width: 11, height: 1,
    art: '☕ COFFEE ☕'
  },
  {
    id: 'food-emoji-row',
    title: 'Snack Row',
    tags: ['decorative'],
    width: 7, height: 1,
    art: '🍔🍟🍕🌮🍣🍩🍦'
  },
  {
    id: 'food-sushi',
    title: 'Sushi',
    tags: ['decorative'],
    width: 5, height: 1,
    art: '🍣🍱🍙🍱🍣'
  },

  // ─────────────────────── ZODIAC / ASTRO ───────────────────────
  {
    id: 'zodiac-stars-line',
    title: 'Cosmic Stars',
    tags: ['aesthetic', 'symbols'],
    width: 17, height: 1,
    art: '☆ ⋆ ✧ ⋆ ☆ ⋆ ✧ ⋆ ☆'
  },
  {
    id: 'zodiac-moon-phases',
    title: 'Moon Phases',
    tags: ['aesthetic', 'nature'],
    width: 9, height: 1,
    art: '🌑🌒🌓🌔🌕🌖🌗🌘🌑'
  },
  {
    id: 'zodiac-leo',
    title: 'Zodiac Leo',
    tags: ['symbols'],
    width: 3, height: 1,
    art: '♌✦♌'
  },
  {
    id: 'zodiac-aries',
    title: 'Zodiac Aries',
    tags: ['symbols'],
    width: 3, height: 1,
    art: '♈✦♈'
  },
  {
    id: 'zodiac-cancer',
    title: 'Zodiac Cancer',
    tags: ['symbols'],
    width: 3, height: 1,
    art: '♋✦♋'
  },
  {
    id: 'zodiac-gemini',
    title: 'Zodiac Gemini',
    tags: ['symbols'],
    width: 3, height: 1,
    art: '♊✦♊'
  },
  {
    id: 'zodiac-pisces',
    title: 'Zodiac Pisces',
    tags: ['symbols'],
    width: 3, height: 1,
    art: '♓✦♓'
  },
  {
    id: 'zodiac-virgo',
    title: 'Zodiac Virgo',
    tags: ['symbols'],
    width: 3, height: 1,
    art: '♍✦♍'
  },
  {
    id: 'zodiac-cosmos',
    title: 'Cosmos',
    tags: ['aesthetic'],
    width: 13, height: 1,
    art: '☆ ⊹ ࣪ ˖ ☾ ˖ ࣪ ⊹ ☆'
  },

  // ─────────────────────── MYSTICAL ───────────────────────
  {
    id: 'mystic-unicorn',
    title: 'Unicorn',
    tags: ['animals', 'aesthetic'],
    width: 5, height: 1,
    art: '🦄✨🌈✨🦄'
  },
  {
    id: 'mystic-fairy',
    title: 'Fairy',
    tags: ['aesthetic'],
    width: 5, height: 1,
    art: '🧚🌸✨🌸🧚'
  },
  {
    id: 'mystic-crystal',
    title: 'Crystal',
    tags: ['aesthetic', 'symbols'],
    width: 7, height: 1,
    art: '💎✨💎✨💎✨💎'
  },
  {
    id: 'mystic-magic',
    title: 'Magic Wand',
    tags: ['aesthetic', 'symbols'],
    width: 9, height: 1,
    art: '✨ ⋆ 🪄 ⋆ ✨'
  },
  {
    id: 'mystic-spell',
    title: 'Spellbook',
    tags: ['aesthetic'],
    width: 7, height: 1,
    art: '📖✨🔮✨📖'
  },

  // ─────────────────────── KAOMOJI EXTRAS ───────────────────────
  {
    id: 'kao-love-eyes',
    title: 'Love Eyes',
    tags: ['kawaii', 'love'],
    width: 6, height: 1,
    art: '(♡ω♡)'
  },
  {
    id: 'kao-sleepy',
    title: 'Sleepy',
    tags: ['kawaii'],
    width: 6, height: 1,
    art: '(￣ω￣) zzz'
  },
  {
    id: 'kao-cry',
    title: 'Cry',
    tags: ['kawaii', 'memes'],
    width: 6, height: 1,
    art: '(っ˘̩╭╮˘̩)っ'
  },
  {
    id: 'kao-flex',
    title: 'Flex',
    tags: ['kawaii', 'memes', 'celebration'],
    width: 7, height: 1,
    art: 'ᕦ(ò_óˇ)ᕤ'
  },
  {
    id: 'kao-evil',
    title: 'Evil Grin',
    tags: ['memes', 'gothic'],
    width: 7, height: 1,
    art: '(¬‿¬)'
  },
  {
    id: 'kao-stars-eyes',
    title: 'Star Eyes',
    tags: ['kawaii', 'celebration'],
    width: 7, height: 1,
    wosRisk: true,
    art: '(☆▽☆)'
  },
  {
    id: 'kao-uwu',
    title: 'UwU',
    tags: ['memes', 'kawaii'],
    width: 3, height: 1,
    art: 'UwU'
  },
  {
    id: 'kao-owo',
    title: 'OwO',
    tags: ['memes', 'kawaii'],
    width: 3, height: 1,
    art: 'OwO'
  },
  {
    id: 'kao-smol',
    title: 'Smol',
    tags: ['kawaii'],
    width: 6, height: 1,
    art: '(✿◕‿◕)'
  },

  // ─────────────────────── ARROWS / NAVIGATION ───────────────────────
  {
    id: 'arrow-right',
    title: 'Right Arrows',
    tags: ['symbols', 'minimalist'],
    width: 11, height: 1,
    art: '➤ ➤ ➤ ➤ ➤'
  },
  {
    id: 'arrow-fancy',
    title: 'Fancy Arrow',
    tags: ['symbols', 'aesthetic'],
    width: 9, height: 1,
    art: '↠ ─── ↠ ─── ↠'
  },
  {
    id: 'arrow-thick',
    title: 'Thick Arrows',
    tags: ['symbols'],
    width: 9, height: 1,
    art: '▶ ▶ ▶ ▶ ▶'
  },

  // ─────────────────────── ENCOURAGEMENT ───────────────────────
  {
    id: 'enc-you-got',
    title: 'You Got This',
    tags: ['sayings'],
    width: 17, height: 1,
    art: '✨ YOU GOT THIS ✨'
  },
  {
    id: 'enc-amazing',
    title: 'Amazing',
    tags: ['sayings', 'celebration'],
    width: 15, height: 1,
    art: '🌟 AMAZING! 🌟'
  },
  {
    id: 'enc-proud',
    title: 'So Proud',
    tags: ['sayings', 'love'],
    width: 15, height: 1,
    art: '💖 SO PROUD 💖'
  },
  {
    id: 'enc-keep-going',
    title: 'Keep Going',
    tags: ['sayings'],
    width: 17, height: 1,
    art: '➤ KEEP GOING ➤'
  },
  {
    id: 'enc-sympathy',
    title: 'Sending Love',
    tags: ['sayings', 'love'],
    width: 17, height: 1,
    art: '🤍 SENDING LOVE 🤍'
  },

  // ─────────────────────── EXTRA FRAMES ───────────────────────
  {
    id: 'frame-cute-tiny',
    title: 'Cute Tiny Frame',
    tags: ['borders', 'aesthetic'],
    width: 13, height: 3,
    wosRisk: true,
    art:
`╭┈┈┈┈┈┈┈┈┈┈┈╮
┊             ┊
╰┈┈┈┈┈┈┈┈┈┈┈╯`
  },
  {
    id: 'frame-stars-corners',
    title: 'Star Corners',
    tags: ['borders', 'aesthetic'],
    width: 13, height: 4,
    wosRisk: true,
    art:
`✦───────────✦
│             │
│             │
✦───────────✦`
  },
  {
    id: 'frame-heart-corners',
    title: 'Heart Corners',
    tags: ['borders', 'love'],
    width: 13, height: 4,
    wosRisk: true,
    art:
`♡───────────♡
│             │
│             │
♡───────────♡`
  },

  // ─────────────── COMMUNITY (from real chat use) ───────────────
  {
    id: 'comm-cat-flowers',
    title: 'Cat in Flowers',
    tags: ['kawaii', 'animals', 'nature', 'aesthetic'],
    width: 22, height: 6,
    wosRisk: true,
    art:
`.               🌸🌼🌸
    　   🌿🌼🌸🌼🌸🌿
         🌿🌸🌼🌸🌼🌸🌿
       ∧,,,∧ 🌸🌼🌸🌿
      (  • · • ) 🌿🌿／
       /    づ   /🎀\\`
  },
  {
    id: 'comm-block-books',
    title: 'Block Books Pair',
    tags: ['decorative'],
    width: 36, height: 11,
    wosRisk: true,
    art:
`.          ◾◾◾                   ◾◾◾
     ◾📔📔📔◾           ◾📔📔📔◾
◾📔📔📔📔📔◾    ◾📔📔📔📔📔◾
◾📔📔📔📔📔◾    ◾📔📔📔📔📔◾
◾📔📔📔📔📔◾    ◾📔📔📔📔📔◾
◾📔📔📔📔📔◾    ◾📔📔📔📔📔◾
◾◽◾◾◽◽◾    ◾◽◾◾◽◽◾
◾📔📔📔📔📔◾    ◾📔📔📔📔📔◾
◾📔📔📔📔📔◾    ◾📔📔📔📔📔◾
     ◾📔📔📔◾           ◾📔📔📔◾
          ◾◾◾                     ◾◾◾`
  },
  {
    id: 'comm-kidnapper-van',
    title: 'Not Kidnapper Van',
    tags: ['memes'],
    width: 22, height: 10,
    wosRisk: true,
    art:
`l┈╭━━━━━━━━━━━─╮
┈┃Not Kidnapper Van┃
┈┃▔▔▔┊┏━┳━┓╭─╮┃
┈┃        ┊┃╱┃╱┃┃▏│┃
╭┻━━┳╯┃╱┃╱┃┃▏│┃
┃┛▂┗┊┈┗━┻━┛╰╥╯┃
┃╰┻╯┊free candy🍭*┈┃
┗▃▃▃▃╭╮▃▃▃▃▃╭╮┘
┈╰╯┈┈╰╯┈┈┈┈┈╰╯
It's totally an ice cream truck!`
  },
  {
    id: 'comm-police-chase',
    title: 'Police Chase',
    tags: ['memes', 'kawaii'],
    width: 30, height: 6,
    art:
`　 　　　　　　/)🚨/)
　　　　　  ／|    (・\`ω\`・)
　　　　 ,σ>)~\`=о⊂二... )
　　　／／/´ ;   /￣___.ﾉ>
　　 '==ベ,＼と.ノ⊂ニコ＼ ＝💨
　　 （⭕） ﾞｰ――――' （⭕）`
  },
  {
    id: 'comm-sniper',
    title: 'Sniper',
    tags: ['memes'],
    width: 30, height: 5,
    wosRisk: true,
    art:
` (\\   (\\
 (  ~_• )
  (っ*︻▇〓*︻┻┳* ─── 💥💥
  /　    )        / \\
( /￣∪       /     \\`
  },
  {
    id: 'comm-cat-sword',
    title: 'Cat with Sword',
    tags: ['memes', 'kawaii', 'animals'],
    width: 50, height: 3,
    art:
`               /\\_/\\
̿̿ ̿̿ ̿̿ ̿'̿'\\̵͇̿̿\\з= ( *  ^  *) =ε/̵͇̿̿/'̿'̿ ̿ ̿̿ ̿̿ ̿̿
Don't ask questions!`
  },
  {
    id: 'comm-cat-sword-kr',
    title: 'Cat with Sword (KR)',
    tags: ['memes', 'kawaii', 'animals', 'nsfw'],
    width: 50, height: 3,
    wosRisk: true,
    art:
`               /\\_/\\
̿̿ ̿̿ ̿̿ ̿'̿'\\̵͇̿̿\\з= ( *  ^  *) =ε/̵͇̿̿/'̿'̿ ̿ ̿̿ ̿̿ ̿̿
 팬티를 벗으세요`
  },
  {
    id: 'comm-cats-hugging',
    title: 'Cats Hugging',
    tags: ['kawaii', 'animals', 'love', 'memes'],
    width: 17, height: 7,
    wosRisk: true,
    art:
`  ∧__∧
(｀•ω• )づ__∧
  つ　 /( •ω•。)
しーＪ (nnノ)
Remember:
No one can use you
if you are useless`
  },
  {
    id: 'comm-cat-cookies',
    title: 'Cookie Cat',
    tags: ['kawaii', 'animals', 'memes'],
    width: 45, height: 6,
    wosRisk: true,
    art:
`.   /\\___/\\
　 (´ ・ω・)　 ＿_
　 /　つ=O===|＿_）🍪
　 し―‐J　　　　　　. 🍪
￣￣￣￣￣￣￣  ｌ🍪. ∧,,∧🍪；|
                |: : 🍪: ( ･᷄-･᷅ ).  🍪 :|
　　　　　　.      .       ＼🍪(∩∩) 🍪ノ`
  },
  {
    id: 'comm-cookie-altar',
    title: 'Cookie Altar Cats',
    tags: ['kawaii', 'animals', 'love', 'celebration'],
    width: 26, height: 6,
    wosRisk: true,
    art:
`💓    /\\ _ /\\        /\\ _ /\\
      ( ˶^ω^˶)     (˶>ω<˶)
     /つ🍪⊂\\   /つ🍪⊂\\
   ┏━━━━━━━┓
     🍪🍪🍪🍪🍪
   ┗━━━━━━━┛`
  },
  {
    id: 'comm-what-mean',
    title: 'WHAT DO YOU MEAN',
    tags: ['memes'],
    width: 45, height: 8,
    wosRisk: true,
    art:
`      /|                              |\\
    /  .\\                            /.  \\
   |     .   \\                         / .   |
    \\__ .\\                     /. __/
           \\-\\ ╭ ⓄⓄ ╮  /-/
             \\\\ ┫_╰╯_┣ //
                  ╰┳--┳.
    WHAT DO YOU MEAN`
  },
  {
    id: 'comm-finger-guns',
    title: 'Finger Guns',
    tags: ['memes', 'animals'],
    width: 50, height: 5,
    wosRisk: true,
    art:
`.                                 (\\(\\
                           /)/)   (  - •)
     ＿＿＿／ᓕ(• •'  ̳)  (＿＿)ᓓ/̵͇̿̿/'̿'̿ ̿ ̿̿
  〱   ╭╌╮￣￣ ∪￣     ____  )  💨  💨
     ￣╰╌╯￣￣￣￣￣╰╌╯￣`
  },
  {
    id: 'comm-angry-cat',
    title: 'Angry Cat Scene',
    tags: ['memes', 'animals', 'kawaii'],
    width: 45, height: 7,
    wosRisk: true,
    art:
`　　　　   彡 ミ　　   /
　　　   (｀･ω･´)　   /
　   ,Oﾞﾞ)=⊂二 ）    /
   ／　ノ((￣＿ノﾆﾆフ
'=-=､＼>>_ﾉ/,.=-＼
（ ◎）ﾞｰ――'（ ◎）      ∩∧＿∧
                    　 …………  ⊂つ+ω+つ`
  },
  {
    id: 'comm-fcku-bunny',
    title: 'Bunny (NSFW)',
    tags: ['memes', 'kawaii', 'animals', 'nsfw'],
    width: 50, height: 3,
    wosRisk: true,
    art:
` (\\__/)  ˚  ○   .   ༓   * ᶠᶜᵏᵧₒᵤ   。࿐ ᶠᶜᵏᵧₒᵤ
(  ｡•ᴗ•)   . ᶠᶜᵏᵧₒᵤ ˚  ࿐  ༶ ᶠᶜᵏᵧₒᵤ .    *    ˖
/ > ཉྀའྀ࿐ ˊˎ  * ᶠᶜᵏᵧₒᵤ ˖   ˚  。○ . ᶠᶜᵏᵧₒᵤ ༓`
  },
  {
    id: 'comm-cat-cookout',
    title: 'Cat Cookout',
    tags: ['kawaii', 'animals', 'celebration'],
    width: 60, height: 7,
    wosRisk: true,
    art:
`                                        .                                       __
                                      / 👀)
                         .-^^^- /   /
 ∧ ,, ∧       __/              /
 (´･ω･ )  <__. | _ |-| _ |
/つ🍺〇━━━⊂二二フ
                      (🔥🔥🔥)`
  },
];
