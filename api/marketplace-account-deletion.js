export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();

  const body = req.body || {};
  const expectedToken = process.env.EBAY_VERIFICATION_TOKEN || "";
  const incomingToken =
    req.headers["x-ebay-verification-token"] ||
    req.headers["x-verification-token"] ||
    body.verificationToken ||
    body.token ||
    "";

  if (!expectedToken || incomingToken !== expectedToken) {
    console.log("Invalid token", { incomingToken });
    return res.status(401).json({ ok: false });
  }

  console.log("Marketplace account deletion payload:", body);
  return res.status(200).json({ ok: true });
}
