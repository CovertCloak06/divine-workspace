/**
 * Frostline — bundled art library.
 * Loaded as a plain <script> (no module system). Defines a global const ART.
 * This file is the source of truth for art content; runtime additions live in Netlify Blobs.
 *
 * Use the editor's "⬇ Download updated art.js" button to regenerate this file
 * with new pieces baked in, then commit it.
 *
 * Per-piece schema:
 *   id            kebab-case unique ID
 *   title         display name
 *   tags          array of tag strings (from the canonical tag list in app.js)
 *   width, height grapheme dimensions
 *   art           the art string (NBSP-spaced)
 *   wosVerified   (optional) true if confirmed working in WoS chat
 *   wosRisk       (optional) true if pre-flagged as potentially broken
 *
 * Spaces below are U+00A0 (non-breaking) where alignment matters.
 */
const ART = [
  {
    id: 'heart-small',
    title: 'Heart (small)',
    tags: ['love', 'symbols'],
    width: 9, height: 7,
    art: '\u3000💛💛💛\u3000💛💛💛\u3000\n💛💛💛💛💛💛💛💛💛\n💛💛💛💛💛💛💛💛💛\n\u3000💛💛💛💛💛💛💛\u3000\n\u3000\u3000💛💛💛💛💛\u3000\u3000\n\u3000\u3000\u3000💛💛💛\u3000\u3000\u3000\n\u3000\u3000\u3000\u3000💛\u3000\u3000\u3000\u3000',
    wosVerified: true,
  },
  {
    id: 'heart-blue',
    title: 'Heart (blue)',
    tags: ['love', 'symbols'],
    width: 9, height: 7,
    art: '\u3000💙💙💙\u3000💙💙💙\u3000\n💙💙💙💙💙💙💙💙💙\n💙💙💙💙💙💙💙💙💙\n\u3000💙💙💙💙💙💙💙\u3000\n\u3000\u3000💙💙💙💙💙\u3000\u3000\n\u3000\u3000\u3000💙💙💙\u3000\u3000\u3000\n\u3000\u3000\u3000\u3000💙\u3000\u3000\u3000\u3000',
    wosVerified: true,
  },
  {
    id: 'snowflake-block',
    title: 'Snowflake (block)',
    tags: ['nature', 'symbols', 'decorative'],
    width: 9, height: 7,
    art: '\u3000\u3000\u3000\u3000❄\u3000\u3000\u3000\u3000\n\u3000\u3000❄\u3000❄\u3000❄\u3000\u3000\n\u3000\u3000\u3000❄❄❄\u3000\u3000\u3000\n❄❄❄❄✦❄❄❄❄\n\u3000\u3000\u3000❄❄❄\u3000\u3000\u3000\n\u3000\u3000❄\u3000❄\u3000❄\u3000\u3000\n\u3000\u3000\u3000\u3000❄\u3000\u3000\u3000\u3000',
    wosVerified: true,
  },
  {
    id: 'star-banner',
    title: 'Star banner',
    tags: ['banners', 'celebration', 'decorative'],
    width: 22, height: 3,
    art: '✦━━━━━━━━━━━━━━━━━━━━✦\n\u3000\u3000\u3000★\u3000CONGRATS\u3000★\u3000\u3000\u3000\n✦━━━━━━━━━━━━━━━━━━━━✦',
  },
  {
    id: 'frost-border',
    title: 'Frost border',
    tags: ['borders', 'nature', 'decorative'],
    width: 22, height: 5,
    art: '❄━━━━━━━━━━━━━━━━━━━━❄\n│\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000│\n│\u3000\u3000\u3000ALLIANCE\u3000CHAT\u3000\u3000\u3000│\n│\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000│\n❄━━━━━━━━━━━━━━━━━━━━❄',
    wosVerified: true,
  },
  {
    id: 'kitty',
    title: 'Kitty',
    tags: ['animals', 'kawaii'],
    width: 9, height: 4,
    art: '\u3000╱|、\n(˚ˎ。7\n\u3000|、˜〵\nじしˍ,)ノ',
  },
  {
    id: 'flower-row',
    title: 'Flower row',
    tags: ['nature', 'decorative', 'minimalist'],
    width: 13, height: 1,
    art: '✿\u3000❀\u3000✾\u3000❀\u3000✿\u3000❀\u3000✾',
    wosVerified: true,
  },
  {
    id: 'arrow-divider',
    title: 'Arrow divider',
    tags: ['borders', 'minimalist'],
    width: 15, height: 1,
    art: '━━━━━━▶\u3000◀━━━━━━',
    wosVerified: true,
  },
  {
    id: 'sparkle-line',
    title: 'Sparkle line',
    tags: ['decorative', 'celebration', 'aesthetic'],
    width: 19, height: 1,
    art: '✦\u3000・\u3000✦\u3000・\u3000✦\u3000・\u3000✦\u3000・\u3000✦\u3000・',
    wosVerified: true,
  },
  {
    id: 'diamond',
    title: 'Diamond',
    tags: ['symbols', 'minimalist'],
    width: 7, height: 4,
    art: '\u3000\u3000\u3000◆\u3000\u3000\u3000\n\u3000\u3000◆\u3000◆\u3000\u3000\n\u3000◆\u3000\u3000\u3000◆\u3000\n◆\u3000\u3000\u3000\u3000\u3000◆',
  },
  {
    id: 'fire',
    title: 'Fire (emoji row)',
    tags: ['celebration', 'symbols'],
    width: 7, height: 1,
    art: '🔥🔥🔥🔥🔥🔥🔥',
    wosVerified: true,
  },
  {
    id: 'hello-banner',
    title: 'Hello banner',
    tags: ['banners', 'sayings'],
    width: 30, height: 5,
    art: '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000HELLO\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\n\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000new\u3000alliance\u3000member\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\n\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\u3000\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
    wosRisk: true,
  },

  /* ============================================================
     Pieces submitted by alliance members.
     Stored as String.raw so backslashes and combining marks
     are preserved verbatim. Width/height auto-calculated on render.
     ============================================================ */

  {
    id: 'cat-guns-noask',
    title: "Don't ask questions",
    tags: ['animals', 'memes', 'sayings'],
    art: String.raw`               /\_/\             
̿̿ ̿̿ ̿̿ ̿'̿'\̵͇̿̿\з= ( *  ^  *) =ε/̵͇̿̿/'̿'̿ ̿ ̿̿ ̿̿ ̿̿
Don't ask questions!`,
  },
  {
    id: 'cat-guns-undies',
    title: '팬티를 벗으세요',
    tags: ['animals', 'memes', 'nsfw'],
    art: String.raw`               /\_/\             
̿̿ ̿̿ ̿̿ ̿'̿'\̵͇̿̿\з= ( *  ^  *) =ε/̵͇̿̿/'̿'̿ ̿ ̿̿ ̿̿ ̿̿
 팬티를 벗으세요`,
  },
  {
    id: 'useless-hug',
    title: 'If you are useless',
    tags: ['animals', 'kawaii', 'sayings', 'memes'],
    art: String.raw`  ∧__∧      
(｀•ω• )づ__∧
  つ　 /( •ω•。)
しーＪ (nnノ)  
Remember:
No one can use you
if you are useless`,
  },
  {
    id: 'cat-cookie',
    title: 'Cat with cookies',
    tags: ['animals', 'kawaii', 'celebration'],
    art: String.raw`   /\___/\     
　 (´ ・ω・)　 ＿_
　 /　つ=O===|＿_）🍪
　 し―‐J　　　　　　. 🍪`,
  },
  {
    id: 'cookie-share',
    title: 'Cookie share',
    tags: ['animals', 'kawaii', 'celebration', 'love'],
    art: String.raw`💓    /\ _ /\ /\ _ /\
      ( ˶^ω^˶) (˶>ω<˶)
     /つ🍪⊂\ /つ🍪⊂\
   ┏━━━━━━━┓
     🍪🍪🍪🍪🍪
   ┗━━━━━━━┛`,
  },
  {
    id: 'what-do-you-mean',
    title: 'What do you mean',
    tags: ['memes', 'sayings'],
    art: String.raw`      /|                              |\
    / .\                            /. \ 
   | .   \                         / .   |
    \__ .\                     /. __/
           \-\ ╭ ⓄⓄ ╮ /-/
             \\ ┫_╰╯_┣ //
                  ╰┳--┳.     
    WHAT DO YOU MEAN`,
  },
  {
    id: 'fuckyou-bunny',
    title: 'Bunny love',
    tags: ['animals', 'kawaii', 'memes', 'nsfw'],
    art: String.raw`(\__/) ˚ ○ . ༓ * ᶠᶜᵏᵧₒᵤ 。࿐ ᶠᶜᵏᵧₒᵤ
( ｡•ᴗ•) . ᶠᶜᵏᵧₒᵤ ˚ ࿐ ༶ ᶠᶜᵏᵧₒᵤ . * ˖
/ > ཉྀའྀ࿐ ˊˎ  * ᶠᶜᵏᵧₒᵤ ˖ ˚ 。○ . ᶠᶜᵏᵧₒᵤ ༓`,
  },
  {
    id: 'beer-fire',
    title: 'Beer & fire',
    tags: ['kawaii', 'celebration', 'memes'],
    art: String.raw`                                        . __
                                      / 👀)
                         .-^^^- / /
 ∧ ,, ∧       __/ /             
 (´･ω･ ) <__. | _ |-| _ |
/つ🍺〇━━━⊂二二フ
                      (🔥🔥🔥)`,
  },
  {
    id: 'garden-cat',
    title: 'Garden cat',
    tags: ['animals', 'kawaii', 'nature', 'decorative'],
    art: '　 🌿🌼🌸🌼🌸🌿\n   🌿🌸🌼🌸🌼🌸🌿\n ∧,,,∧ 🌸🌼🌸🌿\n(  • · • ) 🌿🌿／\n /    づ  /🎀\\',
  },
  {
    id: 'book-stacks',
    title: 'Book stacks',
    tags: ['aesthetic', 'decorative', 'symbols'],
    art: String.raw`     ◾◾◾                   ◾◾◾
  ◾📔📔📔◾           ◾📔📔📔◾
◾📔📔📔📔📔◾ ◾📔📔📔📔📔◾
◾📔📔📔📔📔◾ ◾📔📔📔📔📔◾
◾📔📔📔📔📔◾ ◾📔📔📔📔📔◾
◾📔📔📔📔📔◾ ◾📔📔📔📔📔◾
◾◽◾◾◽◽◾ ◾◽◾◾◽◽◾
◾📔📔📔📔📔◾ ◾📔📔📔📔📔◾
◾📔📔📔📔📔◾ ◾📔📔📔📔📔◾
  ◾📔📔📔◾           ◾📔📔📔◾
     ◾◾◾                   ◾◾◾`,
  },
  {
    id: 'kidnapper-van',
    title: 'Not Kidnapper Van',
    tags: ['memes', 'sayings'],
    art: String.raw`┈╭━━━━━━━━━━━─╮
┈┃Not Kidnapper Van┃
┈┃▔▔▔┊┏━┳━┓╭─╮┃
┈┃ ┊┃╱┃╱┃┃▏│┃
╭┻━━┳╯┃╱┃╱┃┃▏│┃
┃┛▂┗┊┈┗━┻━┛╰╥╯┃
┃╰┻╯┊free candy🍭*┈┃
┗▃▃▃▃╭╮▃▃▃▃▃╭╮┘
┈╰╯┈┈╰╯┈┈┈┈┈╰╯
It's totally an ice cream truck!`,
  },
  {
    id: 'police-cat',
    title: 'Police cat',
    tags: ['animals', 'kawaii', 'memes'],
    art: "　 　　　　　　/)🚨/) 　\n　　　　　 ／| (・`ω`・)　\n　　　　 ,σ>)~`=о⊂二... )　　　\n　　　／／/´ ; /￣___.ﾉ>　　\n　　 '==ベ,＼と.ノ⊂ニコ＼ ＝💨　\n　　 （⭕） ﾞｰ――――' （⭕） 　　　",
  },
  {
    id: 'bunny-gun',
    title: 'Bunny',
    tags: ['animals', 'kawaii', 'memes'],
    art: ' (\\   (\\\n (  ~_• )\n  (っ*︻▇〓*︻┻┳* ─── 💥💥\n  /　    )        / \\\n( /￣∪       /     \\',
  },
];

if (typeof window !== 'undefined') window.ART = ART;
