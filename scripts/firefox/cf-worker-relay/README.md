# Worker configuration

| Name | Type | Required | Default | Description |
|---|---|---|---|---|
| `SECRET` | Secret binding | Yes | None | A non-empty, long random value. Requests must include the matching `secret` query parameter. |

There are no optional environment variables or secret bindings. If `SECRET` is unset, the worker returns HTTP 503.
