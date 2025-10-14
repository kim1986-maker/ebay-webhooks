export default async function handler(req, res) {
  // eBayの保存時に来る疎通チェック対策：GET/HEAD/OPTIONSは200で返す
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") {
    return res.status(200).send("ok");
  }

  if (req.method !== "POST") return res.status(405).end();

  const body = req.body || {};
  const expected = process.env.EBAY_VERIFICATION_TOKEN || "";

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
