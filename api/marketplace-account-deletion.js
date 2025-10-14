import { createHash } from "crypto";

export default async function handler(req, res) {
  // 受信したURL(クエリ除く)から絶対URLを再構成
  const proto = (req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
  const host  = (req.headers.host || "").trim();
  const path  = req.url.split("?")[0]; // /api/marketplace-account-deletion
  const absoluteEndpoint = `${proto}://${host}${path}`; // ← これをハッシュに使う

  if (req.method === "GET") {
    const challengeCode = req.query?.challenge_code || req.query?.challengeCode;
    if (!challengeCode) return res.status(200).send("ok");

    const verificationToken = (process.env.EBAY_VERIFICATION_TOKEN || "").trim();

    const hash = createHash("sha256");
    hash.update(challengeCode);
    hash.update(verificationToken);
    hash.update(absoluteEndpoint);
    const challengeResponse = hash.digest("hex");

    res.setHeader("Content-Type", "application/json");
    return res.status(200).send(JSON.stringify({ challengeResponse }));
  }

  if (req.method === "HEAD" || req.method === "OPTIONS") {
    return res.status(200).send("ok");
  }

  if (req.method !== "POST") return res.status(405).end();

  const expected = (process.env.EBAY_VERIFICATION_TOKEN || "").trim();
  const body = req.body || {};
  const incoming =
    req.headers["x-ebay-verification-token"] ||
    req.headers["x-verification-token"] ||
    body.verificationToken ||
    body.token ||
    (req.query ? req.query.verificationToken || req.query.token : "") ||
    "";

  if (!expected || incoming !== expected) {
    console.log("Invalid token", { incomingToken: incoming });
    return res.status(401).json({ ok: false });
  }

  console.log("MAD webhook payload:", body);
  return res.status(200).json({ ok: true });
}
