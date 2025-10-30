import { createHash } from "crypto";

const TOKEN = (process.env.EBAY_VERIFICATION_TOKEN_ZOROKU || "").trim();

export default async function handler(req, res) {
  const proto = (req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
  const host  = (req.headers.host || "").trim();
  const path  = req.url.split("?")[0];
  const endpoint = `${proto}://${host}${path}`;

  if (req.method === "GET") {
    const code = req.query?.challenge_code || req.query?.challengeCode;
    if (!code) return res.status(200).send("ok");
    const h = createHash("sha256");
    h.update(code); h.update(TOKEN); h.update(endpoint);
    res.setHeader("Content-Type", "application/json");
    return res.status(200).send(JSON.stringify({ challengeResponse: h.digest("hex") }));
  }

  if (req.method === "HEAD" || req.method === "OPTIONS") return res.status(200).send("ok");
  if (req.method !== "POST") return res.status(405).end();

  const body = req.body || {};
  const incoming =
    req.headers["x-ebay-verification-token"] ||
    req.headers["x-verification-token"] ||
    body.verificationToken ||
    body.token ||
    (req.query ? req.query.verificationToken || req.query.token : "") || "";

  if (incoming && TOKEN && incoming !== TOKEN) {
    console.log("[ZOROKU] Token mismatch", { incomingToken: incoming });
    return res.status(401).json({ ok: false });
  }

  console.log("[ZOROKU] MAD webhook payload:", body);
  return res.status(200).json({ ok: true });
}
