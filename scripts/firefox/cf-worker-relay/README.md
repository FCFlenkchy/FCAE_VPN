# Worker configuration

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `SECRET` | Secret binding | Yes | None | A custom, non-empty value. Use at least 32 randomly generated URL-safe characters. |

The script does not enforce a specific secret length. There are no optional environment variables or secret bindings. If `SECRET` is unset, the worker returns HTTP 503.

Example relay URL:

```text
https://relay.example.com/path?secret=YOUR_SECRET
```

Replace the address with your deployed worker URL and `YOUR_SECRET` with the matching `SECRET` value. The URL contains the secret, so keep it private.
