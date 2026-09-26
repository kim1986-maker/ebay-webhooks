import { createHash } from "crypto";

export default async function handler(req, res) {

  // 実際にeBayから呼ばれたEndpoint URLを再構成
  const proto =
    (req.headers["x-forwarded-proto"] || "https")
      .split(",")[0]
      .trim();

  const host =
    (req.headers.host || "")
      .trim();

  const path =
    req.url.split("?")[0];

  const absoluteEndpoint =
    `${proto}://${host}${path}`;

  // ==========================================================
  // 1. eBay Destination Challenge Verification
  // ==========================================================

  if (req.method === "GET") {

    const challengeCode =
      req.query?.challenge_code ||
      req.query?.challengeCode ||
      "";

    // challenge以外の通常GET
    if (!challengeCode) {
      return res
        .status(200)
        .json({
          ok: true,
          service: "eBay message notification webhook"
        });
    }

    const verificationToken =
      String(
        process.env.EBAY_MESSAGE_VERIFICATION_TOKEN || ""
      ).trim();

    if (!verificationToken) {

      console.error(
        "[eBay message webhook] EBAY_MESSAGE_VERIFICATION_TOKEN is missing"
      );

      return res
        .status(500)
        .json({
          error: "verification token missing"
        });
    }

    // eBay仕様：
    // challengeCode + verificationToken + endpoint
    const hash =
      createHash("sha256");

    hash.update(
      String(challengeCode)
    );

    hash.update(
      verificationToken
    );

    hash.update(
      absoluteEndpoint
    );

    const challengeResponse =
      hash.digest("hex");

    console.log(
      "[eBay message webhook] challenge received"
    );

    console.log(
      "[eBay message webhook] endpoint:",
      absoluteEndpoint
    );

    console.log(
      "[eBay message webhook] challengeResponse length:",
      challengeResponse.length
    );

    res.setHeader(
      "Content-Type",
      "application/json"
    );

    return res
      .status(200)
      .json({
        challengeResponse
      });
  }

  // ==========================================================
  // 2. HEAD / OPTIONS
  // ==========================================================

  if (
    req.method === "HEAD" ||
    req.method === "OPTIONS"
  ) {
    return res
      .status(200)
      .send("ok");
  }

  // ==========================================================
  // 3. POST
  //
  // 今はDestination認証テストのみ。
  // 実際の通知保存処理は認証成功後に追加する。
  // ==========================================================

  if (req.method === "POST") {

    console.log(
      "[eBay message webhook] POST received - test mode"
    );

    return res
      .status(200)
      .json({
        received: true
      });
  }

  // ==========================================================
  // その他
  // ==========================================================

  return res
    .status(405)
    .json({
      error: "Method Not Allowed"
    });
}
