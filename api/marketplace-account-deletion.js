import { createHash } from "crypto";

export default async function handler(req, res) {
  // 1) eBayの保存時検証：GETに ?challenge_code=xxx が付いて来る
  if (req.method === "GET") {
    const challengeCode = req.query?.challenge_code || req.query?.challengeCode;
    if (!challengeCode) return res.status(200).send("ok"); // 素のGETはok返しでも可

    // ★検証に使う値：順番は challengeCode → verificationToken → endpoint
    const verificationToken = process.env.EBAY_VERIFICATION_TOKEN || "";
    // endpoint は“eBayに登録した完全一致のURL”を環境変数で持つのが安全
    const endpoint = process.env.EBAY_ENDPOINT_URL || "";

    // ハッシュ計算（SHA-256, hex）
    const hash = createHash("sha256");
    hash.update(challengeCode);
    hash.update(verificationToken);
    hash.update(endpoint);
    const challengeResponse = hash.digest("hex");

    res.setHeader("Content-Type", "application/json");
    return res.status(200).send(JSON.stringify({ challengeResponse }));
  }

  // 2) プリフライト等は200でOK
  if (req.method === "HEAD" || req.method === "OPTIONS") {
    return res.status(200).send("ok");
  }

  // 3) 本番の通知（POST）
  if (req.method !== "POST") return res.status(405).end();

  const expected = process.env.EBAY_VERIFICATION_TOKEN || "";
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
