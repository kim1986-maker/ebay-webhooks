import { createHash } from "crypto";

export default async function handler(req, res) {

  // ==========================================================
  // 実際にeBayから呼ばれたEndpoint URLを再構成
  // ==========================================================

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

    // eBay Destination Challenge
    //
    // challengeCode
    // + verificationToken
    // + endpoint
    //
    // をSHA-256

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
  // 3. eBay Notification POST
  //
  // 現在は「調査モード」
  //
  // ・Google Sheetsへ保存しない
  // ・GASへ転送しない
  // ・Gmailを変更しない
  // ・eBayへ返信しない
  //
  // 受信payloadの構造をVercel Logsで確認するだけ
  // ==========================================================

  if (req.method === "POST") {

    console.log(
      "========================================"
    );

    console.log(
      "[eBay message webhook] POST received"
    );

    console.log(
      "[eBay message webhook] endpoint:",
      absoluteEndpoint
    );


    // ----------------------------------------------------------
    // eBay Signatureヘッダー確認
    // ----------------------------------------------------------

    const ebaySignature =
      req.headers["x-ebay-signature"] || "";

    console.log(
      "[eBay message webhook] X-EBAY-SIGNATURE present:",
      ebaySignature ? "YES" : "NO"
    );


    // ----------------------------------------------------------
    // Content-Type確認
    // ----------------------------------------------------------

    console.log(
      "[eBay message webhook] content-type:",
      req.headers["content-type"] || ""
    );


    // ----------------------------------------------------------
    // Payload確認
    // ----------------------------------------------------------

    let payload = req.body;

    // 念のため文字列で届いた場合にも対応
    if (typeof payload === "string") {

      try {

        payload =
          JSON.parse(payload);

      } catch (error) {

        console.error(
          "[eBay message webhook] JSON parse failed:",
          error.message
        );

        console.log(
          "[eBay message webhook] raw body:",
          payload
        );

        return res
          .status(200)
          .json({
            received: true
          });
      }
    }


    console.log(
      "[eBay message webhook] payload:"
    );

    console.log(
      JSON.stringify(
        payload,
        null,
        2
      )
    );


    // ----------------------------------------------------------
    // よく使いそうな項目を個別確認
    // ----------------------------------------------------------

    const metadata =
      payload?.metadata || {};

    const notification =
      payload?.notification || {};

    console.log(
      "[eBay message webhook] topic:",
      metadata?.topic || ""
    );

    console.log(
      "[eBay message webhook] schemaVersion:",
      metadata?.schemaVersion || ""
    );

    console.log(
      "[eBay message webhook] notificationId:",
      metadata?.notificationId || ""
    );

    console.log(
      "[eBay message webhook] publishDate:",
      metadata?.publishDate || ""
    );

    console.log(
      "[eBay message webhook] notification keys:",
      Object.keys(notification || {}).join(", ")
    );


    console.log(
      "[eBay message webhook] TEST MODE - no data saved"
    );

    console.log(
      "========================================"
    );


    // eBayには正常受信として200を返す
    return res
      .status(200)
      .json({
        received: true
      });
  }


  // ==========================================================
  // 4. その他のHTTP Method
  // ==========================================================

  return res
    .status(405)
    .json({
      error: "Method Not Allowed"
    });
}
