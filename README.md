# Email Tracking Pixel Server

A Node.js server that tracks email opens using an invisible 1×1 GIF pixel,
collecting device, location, and email client data with a protected dashboard API.

## How it works

Embed this in any email:
```html
<img src="https://your-server.com/track/UNIQUE_ID" width="1" height="1" />
```

When the recipient opens the email, the pixel fires and logs: IP address + geolocation,
device type (mobile/tablet/desktop), browser, OS, email client (Gmail, Outlook, Apple Mail...),
open count, first/last open timestamps, and full request headers.

## API Endpoints

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /track/:trackingId` | None | Tracking pixel (returns 1×1 GIF) |
| `GET /api/tracking` | ✅ | All tracking records (paginated) |
| `GET /api/tracking/:id` | ✅ | Details for a specific tracking ID |
| `GET /api/stats` | ✅ | Aggregated stats (devices, browsers, geo, email clients) |
| `GET /health` | None | Server + DB status |

Protected endpoints use HTTP Basic Auth.

## Tech Stack

Node.js, Express, MongoDB (Mongoose), `geoip-lite`, `ua-parser-js`, `helmet`, `express-rate-limit`

## Setup

```bash
npm install
cp .env.example .env   # set your config
node server.js
```

Requires MongoDB running locally on port 27017.

## Author

KOHIL Islam – USTHB, 2025–2026
