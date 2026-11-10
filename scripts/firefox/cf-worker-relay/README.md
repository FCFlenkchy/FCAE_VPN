# Worker configuration

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `SECRET` | Secret binding | Yes | None | A custom, non-empty value. Use at least 32 randomly generated URL-safe characters. |

The binding name must be exactly `SECRET` (uppercase). The script does not enforce a specific secret length. There are no optional environment variables or secret bindings. If `SECRET` is unset, the worker returns HTTP 503.

Example relay URL:

```text
https://relay.example.com/YOUR_SECRET
```

Replace the hostname with your deployed worker address and `YOUR_SECRET` with the matching `SECRET` value. Existing URLs using `?secret=YOUR_SECRET` also work. The URL contains the secret, so keep it private.

Default relay: [https://fcaevpn.fcaevpn.workers.dev/fcaevpn](https://fcaevpn.fcaevpn.workers.dev/fcaevpn). It is shared and may be rate limited; deploying your own relay is recommended. Clear the relay URL to disable it. Relay operators can see relayed account requests and tokens.
