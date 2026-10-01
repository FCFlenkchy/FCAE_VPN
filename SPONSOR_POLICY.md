# FCAE Sponsorship Policy

FCAE may show a small sponsor card under the **SPONSORS** header of the application. Sponsorship does not imply that a sponsor controls FCAE, its networking behavior, or its development decisions.

## Applying

To discuss a sponsorship, campaign availability, or payment, contact **[@mronoob on Telegram](https://t.me/mronoob)**. This is the official sponsorship contact listed by the project.

Acceptance is discretionary. Do not send payment until the campaign, dates, creative, price, and payment method have been agreed through the official contact. Payment does not guarantee approval, continued placement, or endorsement, and no third party is authorized to collect sponsorship payments on FCAE's behalf unless this policy is updated to identify them.

### Required in every application

- sponsor name;
- HTTPS destination URL;
- requested start and end dates;
- confirmation that the applicant owns or is authorized to use every submitted logo, trademark, image, sound, and statement.

### Optional

Everything else is optional. A campaign may be text-only, media-only, or both:

- campaign title and short message;
- icon (foreground art) and background, each a still image, animated GIF, or MP4 video;
- audio narration or sound;
- presentation preferences: colors, positions, sizes, opacity, image fit, and display time.

Every supported option is listed in the [field reference](#field-reference). For the best result, read [Recommended: put your text in your media](#recommended-put-your-text-in-your-media) before preparing creative.

## Content that is not accepted

FCAE does not accept sponsorship for:

- adult, pornographic, sexually explicit, or NSFW content;
- malware, spyware, unwanted software, credential theft, or circumvention of security controls;
- illegal goods, services, or activity;
- misleading financial, investment, medical, health, or security claims;
- hate, harassment, exploitation, or violent extremist content;
- political campaigning or targeted political persuasion;
- tracking pixels, fingerprinting, hidden analytics, redirects intended to identify users, or URLs containing per-user identifiers;
- content that infringes copyright, trademark, privacy, publicity, or other third-party rights.

FCAE may reject or remove any campaign that creates legal, security, privacy, reputational, or user-safety concerns.

## Manifest format

Campaigns are published in [`sponsors.json`](sponsors.json) as a `sponsors` array. The smallest valid campaign is:

```json
{
  "sponsors": [
    {
      "id": "example-2026",
      "destination_url": "https://example.com/"
    }
  ]
}
```

A full campaign using every supported field:

```json
{
  "sponsors": [
    {
      "id": "example-2026",
      "destination_url": "https://example.com/",
      "enabled": true,
      "starts_at": 1790812800,
      "ends_at": 1793491199,
      "duration_seconds": 10,

      "title": "Example Sponsor",
      "message": "A short optional sponsor message.",
      "title_color": "#FFFFFFFF",
      "message_color": "#FFD8E7FF",
      "title_x": 50,
      "title_y": 50,
      "message_x": 50,
      "message_y": 72,
      "title_scale": 100,
      "message_scale": 100,

      "icon_url": "https://cdn.example.com/fcae/example.webp",
      "icon_x": 50,
      "icon_y": 25,
      "icon_scale": 100,
      "icon_opacity": 100,
      "image_fit": "contain",

      "background_url": "https://cdn.example.com/fcae/example-background.mp4",
      "background_color": "#FF142A44",
      "background_scale": 100,
      "background_opacity": 42,
      "background_color_opacity": 100,

      "audio_url": "https://cdn.example.com/fcae/example.mp3"
    }
  ]
}
```

### Field reference

Only `id` and `destination_url` are required. An omitted optional field uses its default.

#### Campaign

| Field | Type | Required | Default | Accepted values |
|---|---|---|---|---|
| `id` | string | **yes** | — | 1–64 characters: `A–Z`, `a–z`, `0–9`, `-`, `_`. Unique within the manifest. Also names the campaign's cache directory. |
| `destination_url` | string | **yes** | — | `https://` URL, ASCII, at most 511 characters. Opened in the external browser only when the user clicks. |
| `enabled` | boolean | no | `true` | `false` keeps the entry in the manifest without showing or caching it. |
| `starts_at` | integer | no | always eligible | Unix timestamp in seconds, UTC. The campaign appears at this second. |
| `ends_at` | integer | no | never expires | Unix timestamp in seconds, UTC. The campaign is shown through this second, then removed with its cache. Must be greater than `starts_at`. |
| `duration_seconds` | integer | no | `10` | 1–3600. How long this card stays on screen before rotating, when two or more campaigns are active. |

#### Text

| Field | Type | Required | Default | Accepted values |
|---|---|---|---|---|
| `title` | string | no | no title | At most 96 bytes of UTF-8 (96 Latin characters, about 48 Persian or 32 Chinese characters). No control characters. |
| `message` | string | no | no message | At most 256 bytes of UTF-8. Line breaks (`\n`) are allowed; other control characters are not. |
| `title_color` | string | no | `#FFFFFFFF` | `#RRGGBB` or `#AARRGGBB`. |
| `message_color` | string | no | `#FFD8E7FF` | `#RRGGBB` or `#AARRGGBB`. |
| `title_x`, `title_y` | integer | no | `50`, `50` | 0–100, percent of the card. X is the horizontal centre of the text block; Y is measured from the top of the usable card area. |
| `message_x`, `message_y` | integer | no | `50`, `72` | 0–100, as above. |
| `title_scale` | integer | no | `100` | 50–200 percent of the base title size (16 sp on Android; the UI font size on desktop). Aliases: `title_size`, `title_font_scale`, `title_font_size`, `title_scale_percent`. |
| `message_scale` | integer | no | `100` | 50–200 percent of the base message size, which is 7/8 of the title's on both platforms (14 sp on Android). Aliases: `message_size`, `message_font_scale`, `message_font_size`, `message_scale_percent`. |

Text blocks are clamped so their text always stays inside the card. If the title and message would overlap, the lower one is moved just below the upper one, and both are lifted if needed to stay on the card. The desktop card is shorter than Android's (80 px against 140 dp), so the same scale fills a larger share of it; keep long text at 100 or below.

#### Icon (foreground media)

The icon is fitted into a media band that spans the card's width and is half the card's height: 70 dp on Android and 40 px on desktop. `image_fit` decides how it fits the band, then `icon_scale` resizes the result.

| Field | Type | Required | Default | Accepted values |
|---|---|---|---|---|
| `icon_url` | string | no | no icon | `https://` URL, ASCII, at most 2048 characters. PNG, JPEG, WebP, GIF, or MP4. |
| `icon_x`, `icon_y` | integer | no | `50`, `25` | 0–100, percent position of the icon's centre. The drawn icon is clamped inside the card, so 0 and 100 anchor it to an edge; an icon wider or taller than the card is centred on that axis. |
| `icon_scale` | integer | no | `100` | 50–160 percent of the fitted size, in both fit modes. Above 100 the icon grows beyond its band; anything past the card's edge is cut off. Aliases: `icon_size`, `icon_size_percent`, `icon_scale_percent`, `image_size`. |
| `icon_opacity` | integer | no | `100` | 0–100 percent. |
| `image_fit` | string | no | `contain` | How the icon fits its box: `contain` shows all of it, `cover` fills the box and crops the overflow. |

#### Background

| Field | Type | Required | Default | Accepted values |
|---|---|---|---|---|
| `background_url` | string | no | card color only | `https://` URL, ASCII, at most 2048 characters. PNG, JPEG, WebP, GIF, or MP4. Always fills the whole card, centred, cropping whatever overflows. |
| `background_color` | string | no | `#FF142A44` | `#RRGGBB` or `#AARRGGBB`. The card's base color. |
| `background_color_opacity` | integer | no | `100` | 0–100 percent. Multiplies the alpha of `background_color`. |
| `background_scale` | integer | no | `100` | 50–160 percent. Aliases: `background_size`, `bg_size`, `bg_scale`, `background_scale_percent`. |
| `background_opacity` | integer | no | `42` | 0–100 percent. The default dims the background so text stays readable. |

#### Audio

| Field | Type | Required | Default | Accepted values |
|---|---|---|---|---|
| `audio_url` | string | no | soundtrack of the campaign's MP4, if any | `https://` URL, ASCII, at most 2048 characters. MP3, AAC/M4A, FLAC, WAV, or Ogg Vorbis. |

### Validation

Mistakes in optional presentation fields never take a campaign down. Mistakes in identity, scheduling, or JSON structure reject the whole manifest; clients then keep the last valid cached manifest.

| Problem | Result |
|---|---|
| Invalid optional value: out-of-range number, malformed color, unknown `image_fit`, non-HTTPS media URL, over-long `message` | That field alone is ignored and its default is used. |
| Media that fails to download or decode, or exceeds the media limits | That plane is dropped; the card falls back to its text on `background_color`. |
| Unknown field names | Ignored. |
| Missing or invalid `id` or `destination_url`; duplicate `id`; invalid `title`; `starts_at` not before `ends_at` | **Whole manifest rejected.** |
| Wrong JSON type, such as a quoted number (`"50"`), a negative or fractional number, or `null` for `title` | **Whole manifest rejected.** |
| More than 32 entries (disabled and expired entries count) or a file larger than 128 KiB | **Whole manifest rejected.** |

Write numbers without quotes, and omit a field instead of setting it to `null`.

## Recommended: put your text in your media

We recommend designing your text into your artwork and leaving `title` and `message` out. FCAE's native text is a fallback, not a design tool:

- **Scripts.** The desktop client draws text with a built-in font that covers basic Latin only. Persian, Arabic, Chinese, emoji, and right-to-left text do not display correctly there. Text inside an image or video looks the same on every platform.
- **Consistency.** Native text uses a different font, size, and line wrapping on Android and desktop. Artwork keeps your typeface, colors, and layout exactly as designed.
- **Branding.** Logos, custom fonts, and styled headlines are only possible in media.

### How to do it

1. Use `background_url` for the artwork, because the background covers the largest area of the card. The icon band is short (40 px on desktop, 70 dp on Android), so it suits a logo but not readable text.
2. Set `"background_opacity": 100`. The default of 42 deliberately dims the background behind native text and would fade your artwork.
3. Leave out `title` and `message` so native text is not drawn over your artwork.
4. Set `background_color` to your artwork's dominant color. It is what users see before the media has downloaded.

### Designing the artwork

The card is a wide strip whose shape differs by platform: 140 dp tall and the screen width minus 40 dp on Android (about 320 × 140 dp, 2.3 : 1, on a typical phone), 80 px tall and 280–380 px wide on desktop (3.5–4.75 : 1). The background is centred and cropped to fit, so the edges may be cut off.

- Design at **800 × 300 px** (MP4 may be larger and is downscaled).
- Keep all text and logos inside the **centre 680 × 160 px**. That area is visible on every platform; the rest may be cropped.
- Use bold lettering at least **40 px tall** in the 800 × 300 design, with strong contrast. The desktop card shows the artwork at about a third to a half of its size, and Android keeps media at 320 × 180 px to save memory, so fine detail softens.
- For animation, prefer MP4 over GIF: it is far smaller for the same quality and is less likely to be merged into coarser frames.

A media-first campaign looks like this:

```json
{
  "id": "example-2026",
  "destination_url": "https://example.com/",
  "background_url": "https://cdn.example.com/fcae/example-800x300.mp4",
  "background_opacity": 100,
  "background_color": "#FF0B1F3A",
  "starts_at": 1790812800,
  "ends_at": 1793491199
}
```

**Trade-off.** Media is downloaded only while the VPN is connected and is cached after that. Until the first download finishes, or if the file fails to decode, a card without `title` or `message` shows only `background_color`. If you want text in that case too, add a short Latin-script `title` and leave room for it in your artwork at its position (`title_x`, `title_y`).

## Media requirements

| | Icon and background | Audio |
|---|---|---|
| Transport | HTTPS only; redirects must stay HTTPS, at most 3 | same |
| Formats | PNG, JPEG, WebP, GIF, MP4 | MP3, AAC/M4A, FLAC, WAV, Ogg Vorbis |
| Maximum file size | 15 MiB per asset | 15 MiB |
| Maximum dimensions | Still images and GIFs: 800 × 450 px. MP4: 1920 × 1080 px, downscaled on decode. | — |

- All media is downscaled to the card canvas it is shown in (400 × 225 on desktop, 320 × 180 on Android). Larger sources gain nothing on screen.
- Animated GIF and MP4 decode at most 180 source frames and play at no more than 30 fps; each frame is shown for 20 ms to 10 s.
- Each card retains at most 6 MiB (Android) or 12 MiB (desktop) of decoded frames across its icon and background. A longer animation is merged into fewer, longer frames that keep its full duration, so it plays coarser instead of disappearing. The icon is decoded before the background.
- Without `audio_url`, a campaign's MP4 icon or background soundtrack is played instead, with no separate download. Media without an audio track is silent. When both exist, `audio_url` wins.

## Presentation

- Sponsor cards are drawn natively by FCAE. Sponsors cannot supply HTML, JavaScript, fonts, or layout code; the fields above are the complete list of what can be customized.
- The card has a fixed height (140 dp on Android, 80 px on desktop), so missing media or different scales never move the rest of the interface.
- With one active campaign it stays in place. With two, they alternate. With three or more, FCAE picks randomly without repeating the card just shown. Each card stays for its `duration_seconds`; users may also swipe or drag to the next card.
- `starts_at` and `ends_at` are honored while the client runs: a campaign appears and disappears at those moments without waiting for a manifest refresh.
- When the app is minimized or in the background, the card keeps the still it was showing and rotation pauses; every other decoded frame is released. Animation resumes when the app returns.
- Audio is off by default. It plays only after the user turns on the card's sound control, and is downloaded only at that point.

## Privacy

- The manifest and all sponsor media are fetched only while the VPN is connected, and only through the connected session's local tunnel proxy. Without a tunnel proxy, nothing is fetched; cached content stays usable offline.
- The manifest is refreshed automatically at most once every 12 hours, tracked by a persisted timestamp that survives restarts. Pressing the sponsor refresh button requests an immediate refresh while connected.
- Destination URLs are never prefetched. They open in the user's external browser only after an explicit click, and the destination site is governed by its own privacy practices.
- Showing, rotating, or swiping a card sends no request. FCAE does not provide sponsors with device identifiers, user profiles, browsing activity, impression reports, or click reports.

## Cache lifecycle

FCAE keeps the sponsor cache small and self-cleaning, and never at the user's expense:

- Each active campaign has its own cache directory, named after its `id`, holding its metadata and separate media, background, and audio directories. Disabled and not-yet-started campaigns are not cached.
- A campaign that leaves the manifest, or whose `ends_at` passes, has its whole cache directory deleted immediately.
- Within a campaign, only the asset the manifest currently points at plus one newest fallback per plane is kept. Older copies and their decoded sidecars are removed on every accepted manifest.
- Decoded pixels are held in memory only for the visible card and the already-selected next card, which is prepared in the background before rotation.
- When the cache exceeds its ceiling, decoded sidecars are discarded first (they can be re-derived), then fallback copies and clips of cards not on screen. Assets of the card being shown are never deleted.
- Interrupted writes are staged in `.<name>.<kind>.tmp` files and swept on every manifest pass, so a crash cannot leave partial files behind.
- The whole cache is capped at 768 MiB.
