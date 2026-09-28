# FCAE Sponsorship Policy

FCAE may show a small, clearly labeled **Sponsored** card in the application. Sponsorship does not imply that a sponsor controls FCAE, its networking behavior, or its development decisions.

## Applying

To discuss a sponsorship, campaign availability, or payment, contact **[@mronoob on Telegram](https://t.me/mronoob)**. This is the official sponsorship contact listed by the project.

Acceptance is discretionary. Do not send payment until the campaign, dates, creative, price, and payment method have been agreed through the official contact. Payment does not guarantee approval, continued placement, or endorsement, and no third party is authorized to collect sponsorship payments on FCAE's behalf unless this policy is updated to identify them.

An application must provide:

- sponsor name and campaign title;
- HTTPS destination URL;
- an optional short message and/or final image or animated GIF;
- optional presentation preferences: background image, text/card colors, text alignment, image fit, and image scale;
- requested start and end dates;
- confirmation that the applicant owns or is authorized to use every submitted logo, trademark, image, and statement.

## Content that is not accepted

FCAE does not accept sponsorship for:

- adult, pornographic, sexually explicit, or NSFW content;
- gambling, betting, casinos, lotteries, or similar services;
- malware, spyware, unwanted software, credential theft, or circumvention of security controls;
- illegal goods, services, or activity;
- deceptive claims, impersonation, scams, pyramid schemes, or get-rich-quick schemes;
- misleading financial, investment, medical, health, or security claims;
- hate, harassment, exploitation, or violent extremist content;
- political campaigning or targeted political persuasion;
- tracking pixels, fingerprinting, hidden analytics, redirects intended to identify users, or URLs containing per-user identifiers;
- content that infringes copyright, trademark, privacy, publicity, or other third-party rights.

FCAE may reject or remove any campaign that creates legal, security, privacy, reputational, or user-safety concerns.

## Privacy and presentation

Sponsor cards are rendered by FCAE rather than arbitrary HTML or JavaScript. Images are optional; a card can use a short message with left, center, or right alignment, and FCAE falls back to a safe title/message card when media is absent, rejected, corrupt, or unavailable. Sponsors may provide an optional `background_url`, `text_color`, and `card_color`, plus `text_align`, `image_fit`, and `image_scale` presentation preferences. These controls style the native card only; sponsors cannot supply HTML, JavaScript, fonts, or arbitrary layout code. The sponsor manifest and external `media_url`/`background_url` resources are fetched only after FCAE reports that the VPN is connected, and only through the connected session's local tunnel proxy. If no tunnel proxy is available, FCAE does not fetch them. Destination URLs are never prefetched by FCAE; they are handed to the external browser only after an explicit user click. The small GitHub manifest uses a persisted Unix timestamp and automatic refreshes occur no more than once every 12 hours. An explicit user press of the sponsor refresh button may request an immediate refresh while the VPN is connected. Opening and closing the client UI does not reset the automatic interval; the last valid cached manifest remains available if a refresh fails. Campaigns rotate locally every five seconds and users may swipe or drag the card to move to another sponsor; neither action generates an impression request. With two active campaigns FCAE alternates between them. With three or more, FCAE chooses randomly without immediately repeating the card already shown. A single campaign remains in place.

FCAE does not provide sponsors with device identifiers, user profiles, browsing activity, impression reports, or click reports. Destination links open in the user's external browser. The destination site is governed by its own privacy practices.

## Media requirements

- HTTPS only.
- PNG, JPEG, WebP, or GIF.
- Maximum encoded size: 2 MiB.
- Maximum dimensions: 800 × 450 pixels on every platform.
- Animated GIFs: maximum 120 frames on desktop and 60 on Android.
- `media_url` and `background_url` are optional; each uses the same HTTPS, format, encoded-size, and dimension limits.
- `message` is optional and limited to 256 printable characters.
- `text_color` and `card_color` use `#RRGGBB` or `#AARRGGBB`.
- `text_align` is `left`, `center`, or `right`; it defaults to `center`.
- `image_fit` is `contain` or `cover`; it defaults to `contain`.
- `image_scale` is a percentage from 50 through 160 and defaults to 100.
- Invalid presentation values are ignored and replaced with safe defaults.
- No audio or video.

## Manifest format

Production entries are stored in `sponsors.json`:

```json
{
  "schema_version": 1,
  "sponsors": [
    {
      "id": "example-2026",
      "title": "Example Sponsor",
      "message": "A short optional sponsor message.",
      "media_url": "https://cdn.example.com/fcae/example.webp",
      "background_url": "https://cdn.example.com/fcae/example-background.webp",
      "text_color": "#FFFFFFFF",
      "card_color": "#FF142A44",
      "text_align": "center",
      "image_fit": "contain",
      "image_scale": 100,
      "destination_url": "https://example.com/",
      "enabled": true,
      "starts_at": 1790812800,
      "ends_at": 1793491199
    }
  ]
}
```

`message`, `media_url`, and dates are optional. Dates are Unix timestamps in UTC. A campaign must retain a title and HTTPS destination. Removing a campaign from the manifest causes FCAE to remove its cached media on the next successful refresh.
