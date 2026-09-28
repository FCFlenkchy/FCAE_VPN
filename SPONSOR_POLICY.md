# FCAE Sponsorship Policy

FCAE may show a small, clearly labeled **Sponsored** card in the application. Sponsorship does not imply that a sponsor controls FCAE, its networking behavior, or its development decisions.

## Applying

To discuss a sponsorship, campaign availability, or payment, contact **[@mronoob on Telegram](https://t.me/mronoob)**. This is the official sponsorship contact listed by the project.

Acceptance is discretionary. Do not send payment until the campaign, dates, creative, price, and payment method have been agreed through the official contact. Payment does not guarantee approval, continued placement, or endorsement, and no third party is authorized to collect sponsorship payments on FCAE's behalf unless this policy is updated to identify them.

An application must provide:

- sponsor name and an optional campaign title;
- HTTPS destination URL;
- an optional short message and/or final image or animated GIF; a campaign may be media-only, text-only, or use both;
- optional presentation preferences: background image, title/message/card colors, title/message X/Y positions, image fit, icon scale, and background scale;
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

Sponsor cards are rendered by FCAE rather than arbitrary HTML or JavaScript. The icon and background are optional; a card can use a short message with explicit title/message X/Y positions, and FCAE falls back to a safe title/message card when either resource is absent, rejected, corrupt, or unavailable. Sponsors may provide an optional `background_url`, `title_color`, `message_color`, and `background_color`, plus `title_x`, `title_y`, `message_x`, `message_y`, `image_fit`, `icon_scale`, and `background_scale` presentation preferences. These controls style the native card only; sponsors cannot supply HTML, JavaScript, fonts, or arbitrary layout code. Native clients reserve a fixed 140-unit sponsor card (140dp on Android and 140px on desktop) so missing media or different icon/background scales do not reflow the surrounding interface. The sponsor manifest and external `icon_url`/`background_url` resources are fetched only after FCAE reports that the VPN is connected, and only through the connected session's local tunnel proxy. If no tunnel proxy is available, FCAE does not fetch them; previously cached manifest/media remain usable offline and are not deleted on disconnect. Encoded media is cached for active campaigns, while decoded pixels are loaded on demand for the visible campaign and released when it is no longer current. Destination URLs are never prefetched by FCAE; they are handed to the external browser only after an explicit user click. The small GitHub manifest uses a persisted Unix timestamp and automatic refreshes occur no more than once every 12 hours. An explicit user press of the sponsor refresh button may request an immediate refresh while the VPN is connected. Opening and closing the client UI does not reset the automatic interval; the last valid cached manifest remains available if a refresh fails. Campaigns rotate locally every ten seconds and users may swipe or drag the card to move to another sponsor; neither action generates an impression request. With two active campaigns FCAE alternates between them. With three or more, FCAE chooses randomly without immediately repeating the card already shown. A single campaign remains in place.

FCAE does not provide sponsors with device identifiers, user profiles, browsing activity, impression reports, or click reports. Destination links open in the user's external browser. The destination site is governed by its own privacy practices.

## Media requirements

- HTTPS only.
- PNG, JPEG, WebP, or GIF.
- Maximum encoded size: 10 MiB per icon or background asset.
- Maximum dimensions: 800 × 450 pixels on every platform.
- Animated GIFs: maximum 120 frames on desktop and 60 on Android.
- `icon_url` and `background_url` are optional; both accept PNG, JPEG, WebP, or GIF with the same HTTPS, encoded-size, and dimension limits. Animated GIF frames are retained for both the icon and background.
- `title` is optional and limited to 96 printable characters; an omitted title renders no title text.
- `message` is optional and limited to 256 printable characters.
- `title_x`, `title_y`, `message_x`, and `message_y` are integer percentages from 0 through 100, measured from the top-left of the usable card area. Title position defaults to 50,50; message position defaults to 50,72.
- `title_color`, `message_color`, and `background_color` use `#RRGGBB` or `#AARRGGBB`.
- `image_fit` is `contain` or `cover`; it defaults to `contain`.
- `icon_scale` and `background_scale` are percentages from 50 through 160 and default to 100.
- Invalid presentation values are ignored and replaced with safe defaults.
- No audio or video.

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
      "background_url": "https://cdn.example.com/fcae/example-background.webp",
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
      "destination_url": "https://example.com/",
      "enabled": true,
      "starts_at": 1790812800,
      "ends_at": 1793491199
    }
  ]
}
```

`message`, `icon_url`, and dates are optional. Dates are Unix timestamps in UTC. A campaign must retain a title and HTTPS destination. Removing a campaign from the manifest causes FCAE to remove its cached icon/background media on the next successful refresh.
