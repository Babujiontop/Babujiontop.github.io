const http = require("node:http");

const PORT = Number(process.env.PORT || 3000);
const ALLOWED_ORIGIN = "https://babujiontop.github.io";
const PI_ME_URL = "https://api.minepi.com/v2/me";

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;

  res.setHeader("Vary", "Origin");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", "no-store");

  if (origin === ALLOWED_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  }

  if (req.method === "OPTIONS") {
    if (origin !== ALLOWED_ORIGIN) {
      res.writeHead(403);
      return res.end(JSON.stringify({ error: "Origin not allowed" }));
    }
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.writeHead(204);
    return res.end();
  }

  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200);
    return res.end(JSON.stringify({
      status: "ok",
      service: "MIXCOFARM MCFT backend"
    }));
  }

  if (req.method !== "POST" || req.url !== "/api/auth/verify") {
    res.writeHead(404);
    return res.end(JSON.stringify({ error: "Not found" }));
  }

  if (origin !== ALLOWED_ORIGIN) {
    res.writeHead(403);
    return res.end(JSON.stringify({ error: "Origin not allowed" }));
  }

  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 8192) {
      res.writeHead(413);
      return res.end(JSON.stringify({ error: "Request too large" }));
    }
  }

  let input;
  try {
    input = JSON.parse(body);
  } catch {
    res.writeHead(400);
    return res.end(JSON.stringify({ error: "Invalid JSON" }));
  }

  const accessToken = input && input.accessToken;
  if (typeof accessToken !== "string" ||
      accessToken.length < 1 ||
      accessToken.length > 4096) {
    res.writeHead(400);
    return res.end(JSON.stringify({ error: "Access token required" }));
  }

  try {
    const piResponse = await fetch(PI_ME_URL, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json"
      },
      signal: AbortSignal.timeout(10000)
    });

    if (!piResponse.ok) {
      res.writeHead(401);
      return res.end(JSON.stringify({
        error: "Pi authentication could not be verified"
      }));
    }

    const user = await piResponse.json();

    if (!user || typeof user.uid !== "string" ||
        typeof user.username !== "string") {
      res.writeHead(502);
      return res.end(JSON.stringify({
        error: "Unexpected response from Pi"
      }));
    }

    res.writeHead(200);
    return res.end(JSON.stringify({
      verified: true,
      user: {
        uid: user.uid,
        username: user.username
      }
    }));
  } catch {
    res.writeHead(502);
    return res.end(JSON.stringify({
      error: "Pi verification service is temporarily unavailable"
    }));
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`MIXCOFARM backend listening on port ${PORT}`);
});
