const ALLOWED_HOSTS = [
  "mozilla.org", "mozilla.com", "firefox.com",
  "github.com", "githubusercontent.com", "jsdelivr.net",
];

const HOP_HEADERS = new Set([
  "host", "connection", "content-length", "keep-alive", "proxy-authenticate",
  "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
  "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
  "x-real-ip", "true-client-ip", "x-client-ip", "x-cluster-client-ip",
  "x-original-forwarded-for", "via", "cdn-loop", "referer",
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

const INTERNAL_HEADER_PREFIXES = ["cf-", "x-forwarded-", "proxy-", "x-proxy-", "x-fcae-"];
const INTERNAL_HEADERS = new Set(["x-proxy", "x-fcae"]);

function isRelayHeader(name) {
  return name.startsWith("x-") && name.split("-").includes("relay");
}

function requestHeaders(input) {
  const headers = new Headers();
  const connectionHeaders = new Set((input.get("connection") || "").split(",").map((name) => name.trim().toLowerCase()));
  for (const [name, value] of input) {
    const lower = name.toLowerCase();
    if (!HOP_HEADERS.has(lower) && !connectionHeaders.has(lower) && !INTERNAL_HEADERS.has(lower) &&
        !isRelayHeader(lower) && !INTERNAL_HEADER_PREFIXES.some((prefix) => lower.startsWith(prefix))) {
      headers.append(name, value);
    }
  }
  return headers;
}

function authorized(incoming, secret) {
  if (incoming.searchParams.has("secret")) return false;

  const segments = incoming.pathname.split("/");
  if (segments.length < 2 || segments.length > 3 || !segments[1] ||
      (segments.length === 3 && segments[2] !== "")) return false;
  try {
    return decodeURIComponent(segments[1]) === secret;
  } catch {
    return false;
  }
}

export default {
  async fetch(request, env) {
    const secret = env?.SECRET;
    if (typeof secret !== "string" || secret.length === 0) return failure(503, "relay secret is not configured");
    const incoming = new URL(request.url);
    if (!authorized(incoming, secret)) return failure(403, "relay access denied");

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
      for (const name of [...headers.keys()]) if (isRelayHeader(name)) headers.delete(name);
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
