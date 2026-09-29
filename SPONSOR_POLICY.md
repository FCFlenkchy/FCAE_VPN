# FCAE Sponsorship Policy

FCAE may show a small, clearly labeled **Sponsored** card in the application. Sponsorship does not imply that a sponsor controls FCAE, its networking behavior, or its development decisions.

## Applying

To discuss a sponsorship, campaign availability, or payment, contact **[@mronoob on Telegram](https://t.me/mronoob)**. This is the official sponsorship contact listed by the project.

Acceptance is discretionary. Do not send payment until the campaign, dates, creative, price, and payment method have been agreed through the official contact. Payment does not guarantee approval, continued placement, or endorsement, and no third party is authorized to collect sponsorship payments on FCAE's behalf unless this policy is updated to identify them.

An application must provide:

- sponsor name and an optional campaign title;
- HTTPS destination URL;
- an optional short message and/or final image, animated GIF, or MP4 video; a campaign may be media-only, text-only, or use both;
- optional audio narration or sound and presentation preferences: background image/video, title/message/card colors, title/message X/Y positions, image fit, icon scale, and background scale;
- requested start and end dates;
- confirmation that the applicant owns or is authorized to use every submitted logo, trademark, image, and statement.

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

## Privacy and presentation

Sponsor cards are rendered by FCAE rather than arbitrary HTML or JavaScript. The icon and background are optional; a card can use a short message with explicit title/message X/Y positions, and FCAE falls back to a safe title/message card when either resource is absent, rejected, corrupt, or unavailable. Sponsors may provide an optional `background_url`, `audio_url`, `title_color`, `message_color`, and `background_color`, plus `title_x`, `title_y`, `message_x`, `message_y`, `image_fit`, `icon_scale`, and `background_scale` presentation preferences. `icon_url` and `background_url` may contain still images, animated GIFs, or MP4 video; video is decoded to bounded frames by the same native media path. Audio is off by default and the card's own "Sound on"/"Sound off" control enables it: the clip it plays is the campaign's `audio_url` or, when there is none, the soundtrack of the campaign's own MP4, so enabling sound never triggers a second download and FCAE never probes a file for an audio track. A media file with no audio is simply silent. A clip that is still being cached starts as soon as it lands, and one whose decode fails is retried on the rotation after it. These controls style the native card only; sponsors cannot supply HTML, JavaScript, fonts, or arbitrary layout code. Native clients reserve a fixed 140-unit sponsor card (140dp on Android and 140px on desktop) so missing media or different icon/background scales do not reflow the surrounding interface. The sponsor manifest and external `icon_url`/`background_url`/`audio_url` resources are fetched only after FCAE reports that the VPN is connected, and only through the connected session's local tunnel proxy. If no tunnel proxy is available, FCAE does not fetch them; previously cached manifest/media remain usable offline and are not deleted on disconnect. Each active campaign has an isolated cache directory named after its validated manifest ID, containing its campaign metadata and separate media, background, and audio directories. Encoded media is cached for active campaigns. Decoded pixels are retained only for the visible campaign and the already-selected next campaign; the next card is prepared in the background before rotation, and older decoded pixels are released. Every plane -- still, GIF, or video frame -- is retained at a card-sized canvas, so the memory budget decides animation smoothness rather than whether a card has media at all: a clip that would exceed the budget is merged into fewer, longer frames that keep its full duration, and the icon is always served before the background. Audio is downloaded lazily only after the user enables it. Destination URLs are never prefetched by FCAE; they are handed to the external browser only after an explicit user click. The small GitHub manifest uses a persisted Unix timestamp and automatic refreshes occur no more than once every 12 hours. An explicit user press of the sponsor refresh button may request an immediate refresh while the VPN is connected. Opening and closing the client UI does not reset the automatic interval; the last valid cached manifest remains available if a refresh fails. `starts_at` and `ends_at` are honored while the client runs: a campaign whose window closes is removed with its cached media at that moment -- and one whose window opens gets its turn -- instead of waiting for the next refresh. Campaigns rotate locally every ten seconds and users may swipe or drag the card to move to another sponsor; neither action generates an impression request. With two active campaigns FCAE alternates between them. With three or more, FCAE chooses randomly without immediately repeating the card already shown. A single campaign remains in place.

FCAE does not provide sponsors with device identifiers, user profiles, browsing activity, impression reports, or click reports. Destination links open in the user's external browser. The destination site is governed by its own privacy practices.

## Cache lifecycle

FCAE keeps the sponsor cache small and self-cleaning, and never at the user's expense:

- A campaign that leaves the manifest, or whose `ends_at` passes, has its whole cache directory (encoded media, decoded sidecars, metadata) deleted on the spot; disabled or never-started campaigns are not cached at all.
- Within a campaign, only the URL the manifest currently points at plus one newest fallback per plane is kept; older entries and their decoded sidecars are removed on every accepted manifest.
- Decoded sidecars are re-derivable, so they are discarded first when the cache is over its ceiling, followed by fallback copies and the clips of cards that are not on screen. Assets of the card being shown are never deleted: a missing asset is far more expensive than a few megabytes on disk.
- Interrupted writes are staged in `.<name>.<kind>.tmp` files and swept on every manifest pass, so a crash cannot leave partial files behind.
- The whole tree is capped at 192 MiB; campaign media is capped at 15 MiB per asset and unlimited campaigns are not accepted (32 active campaigns maximum).

## Media requirements

- HTTPS only.
- PNG, JPEG, WebP, GIF, or MP4 video for `icon_url` and `background_url`.
- `audio_url` is optional and supports audio formats understood by the Rust decoder, including MP3, WAV, Ogg, and FLAC.
- A campaign without `audio_url` plays the soundtrack of its own media instead: an MP4 `background_url` or `icon_url` is handed to the decoder as it is cached, with no separate download and no audio-track probe. A file with no audio track is silent by design; a plane the image decoder can identify (still image or GIF) is skipped. `audio_url` always wins when both are present.
- Maximum encoded size: 15 MiB per icon, background, or audio asset.
- Maximum dimensions: 800 × 450 pixels on every platform.
- Animated GIFs and MP4 video retain up to 300 decoded source frames and are then merged down to the decoded-byte budget (16 MiB per plane on Android, 64 MiB elsewhere, so roughly 57 retained frames per plane on Android and 129 on desktop); merging preserves the clip's total duration, so a long animation plays coarser rather than disappearing. The icon is served first, then the background.
- `icon_url` and `background_url` are optional and accept PNG, JPEG, WebP, GIF, or MP4 with the same HTTPS, encoded-size, and dimension limits. Animated GIF and video frames are retained for both the icon and background.
- `title` is optional and limited to 96 printable characters; an omitted title renders no title text.
- `message` is optional and limited to 256 printable characters.
- `title_x` and `message_x` are integer percentages from 0 through 100 for the horizontal centre of the title and message blocks; the block is clamped so its text always stays inside the card. `title_y` and `message_y` are integer percentages from 0 through 100 measured from the top of the usable card area. Title position defaults to 50,50; message position defaults to 50,72.
- `duration_seconds` is optional, defaults to 10, and accepts 1 through 3600 seconds.
- `title_color`, `message_color`, and `background_color` use `#RRGGBB` or `#AARRGGBB`.
- `image_fit` is `contain` or `cover`; it defaults to `contain`.
- `icon_scale` and `background_scale` are percentages from 50 through 160 and default to 100. The scaled art is kept inside the card: a larger icon is clamped to the card's edges instead of being cut off.
- `icon_x` and `icon_y` place the icon's centre; the icon is clamped inside the card, so the extremes of the range anchor it to the card's edge.
- Invalid presentation values are ignored and replaced with safe defaults.

## Manifest format

Production entries are stored in `sponsors.json`:

```json
{
  "sponsors": [
    {
      "id": "example-2026",
      "title": "Example Sponsor",
      "message": "A short optional sponsor message.",
      "icon_url": "https://cdn.example.com/fcae/example.webp",
      "background_url": "https://cdn.example.com/fcae/example-background.mp4",
      "audio_url": "https://cdn.example.com/fcae/example.mp3",
      "title_color": "#FFFFFFFF",
      "message_color": "#FFD8E7FF",
      "background_color": "#FF142A44",
      "title_x": 50,
      "title_y": 60,
      "message_x": 50,
      "message_y": 70,
      "image_fit": "contain",
      "icon_scale": 100,
      "background_scale": 100,
      "icon_x": 50,
      "icon_y": 25,
      "duration_seconds": 10,
      "destination_url": "https://example.com/",
      "enabled": true,
      "starts_at": 1790812800,
      "ends_at": 1793491199
    }
  ]
}
```

`message`, `icon_url`, `background_url`, `audio_url`, and dates are optional. Dates are Unix timestamps in UTC. A campaign must retain a title and HTTPS destination. `starts_at` is optional and delays campaign eligibility until its Unix timestamp. Removing a campaign from the manifest causes FCAE to remove its cached icon/background/audio media on the next successful refresh.
