const ALLOWED_HOSTS = [
  "mozilla.org", "mozilla.com", "firefox.com",
  "github.com", "githubusercontent.com", "jsdelivr.net",
];

const HOP_HEADERS = new Set([
  "host", "connection", "content-length", "keep-alive", "proxy-authenticate",
  "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
  "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
  "x-real-ip", "true-client-ip", "cdn-loop", "referer",
]);

function failure(status, message) {
  return new Response(message, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Relay-Error": message },
  });
}

function allowedTarget(raw) {
  let target;
  try {
    target = new URL(raw);
  } catch {
    return null;
  }
  const host = target.hostname.toLowerCase();
  if (target.protocol !== "https:" || target.username || target.password || target.hash || target.port ||
      !ALLOWED_HOSTS.some((domain) => host === domain || host.endsWith(`.${domain}`))) {
    return null;
  }
  return target;
}

function requestHeaders(input) {
  const headers = new Headers();
  const connectionHeaders = new Set((input.get("connection") || "").split(",").map((name) => name.trim().toLowerCase()));
  for (const [name, value] of input) {
    const lower = name.toLowerCase();
    if (!HOP_HEADERS.has(lower) && !connectionHeaders.has(lower) && !lower.startsWith("cf-") && !lower.startsWith("x-forwarded-")) {
      headers.append(name, value);
    }
  }
  return headers;
}

export default {
  async fetch(request, env) {
    const secret = env?.SECRET;
    if (typeof secret !== "string" || secret.length === 0) return failure(503, "relay secret is not configured");
    const incoming = new URL(request.url);
    const supplied = incoming.searchParams.getAll("secret");
    if (supplied.length !== 1 || supplied[0] !== secret) return failure(403, "relay access denied");

    if (incoming.searchParams.get("health") === "1") {
      if (request.method !== "GET") return failure(405, "health requires GET");
      return Response.json({ relay: "fcae-vpn", version: 1, ready: true }, {
        headers: { "Cache-Control": "no-store" },
      });
    }
    const targets = incoming.searchParams.getAll("url");
    if (targets.length === 0) {
      return failure(400, "target is required");
    }
    if (targets.length !== 1) return failure(400, "exactly one target is required");
    const target = allowedTarget(targets[0]);
    if (!target) return failure(403, "target is not allowed");
    if (!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].includes(request.method)) {
      return failure(405, "method is not allowed");
    }

    const init = { method: request.method, headers: requestHeaders(request.headers), redirect: "manual" };
    if (request.method !== "GET" && request.method !== "HEAD") init.body = request.body;
    try {
      const upstream = await fetch(target.toString(), init);
      const headers = new Headers(upstream.headers);
      const connectionHeaders = (headers.get("connection") || "").split(",").map((name) => name.trim());
      for (const name of connectionHeaders) if (name) headers.delete(name);
      for (const name of HOP_HEADERS) headers.delete(name);
      headers.delete("x-relay-error");
      headers.delete("x-arman-relay");
      headers.set("X-FCAE-Relay", "1");
      headers.set("Cache-Control", "no-store");
      return new Response(request.method === "HEAD" ? null : upstream.body, {
        status: upstream.status, statusText: upstream.statusText, headers,
      });
    } catch {
      return failure(502, "upstream request failed");
    }
  },
};
