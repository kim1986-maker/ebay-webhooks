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
  // 現在は調査モード
  //
  // ・署名の存在と構造を確認
  // ・署名本体はログ出力しない
  // ・署名検証はまだ行わない
  // ・Google Sheetsへ保存しない
  // ・GASへ転送しない
  // ・Gmailを変更しない
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


    // ========================================================
    // X-EBAY-SIGNATURE
    // ========================================================

    const ebaySignature =
      String(
        req.headers["x-ebay-signature"] || ""
      ).trim();

    console.log(
      "[eBay message webhook] X-EBAY-SIGNATURE present:",
      ebaySignature ? "YES" : "NO"
    );


    // ========================================================
    // 署名ヘッダーの安全な解析
    //
    // 署名そのものはログに出さない
    // ========================================================

    if (ebaySignature) {

      try {

        const decodedSignatureText =
          Buffer
            .from(
              ebaySignature,
              "base64"
            )
            .toString("utf8");

        const decodedSignature =
          JSON.parse(
            decodedSignatureText
          );


        console.log(
          "[eBay message webhook] signature decoded: YES"
        );

        console.log(
          "[eBay message webhook] signature alg:",
          decodedSignature?.alg || ""
        );

        console.log(
          "[eBay message webhook] signature kid:",
          decodedSignature?.kid || ""
        );

        console.log(
          "[eBay message webhook] signature digest:",
          decodedSignature?.digest || ""
        );


        const signatureBody =
          String(
            decodedSignature?.signature || ""
          );

        console.log(
          "[eBay message webhook] signature body present:",
          signatureBody ? "YES" : "NO"
        );

        console.log(
          "[eBay message webhook] signature body length:",
          signatureBody.length
        );


      } catch (error) {

        console.error(
          "[eBay message webhook] signature decode failed:",
          error.message
        );
      }

    }


    // ========================================================
    // Content-Type
    // ========================================================

    console.log(
      "[eBay message webhook] content-type:",
      req.headers["content-type"] || ""
    );


    // ========================================================
    // Payload
    // ========================================================

    let payload =
      req.body;


    if (typeof payload === "string") {

      try {

        payload =
          JSON.parse(payload);

      } catch (error) {

        console.error(
          "[eBay message webhook] JSON parse failed:",
          error.message
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


    // ========================================================
    // Payload主要項目
    // ========================================================

    const metadata =
      payload?.metadata || {};

    const notification =
      payload?.notification || {};

    const data =
      notification?.data || {};


    console.log(
      "[eBay message webhook] topic:",
      metadata?.topic || ""
    );

    console.log(
      "[eBay message webhook] schemaVersion:",
      metadata?.schemaVersion || ""
    );

    // 前回の参照位置を修正
    console.log(
      "[eBay message webhook] notificationId:",
      notification?.notificationId || ""
    );

    console.log(
      "[eBay message webhook] publishDate:",
      notification?.publishDate || ""
    );

    console.log(
      "[eBay message webhook] notification keys:",
      Object.keys(notification).join(", ")
    );

    console.log(
      "[eBay message webhook] data keys:",
      Object.keys(data).join(", ")
    );


    // ========================================================
    // 現在は保存しない
    // ========================================================

    console.log(
      "[eBay message webhook] SIGNATURE INSPECTION MODE"
    );

    console.log(
      "[eBay message webhook] signature verification: NOT YET IMPLEMENTED"
    );

    console.log(
      "[eBay message webhook] no data saved"
    );

    console.log(
      "========================================"
    );


    return res
      .status(200)
      .json({
        received: true
      });
  }


  // ==========================================================
  // 4. その他
  // ==========================================================

  return res
    .status(405)
    .json({
      error: "Method Not Allowed"
    });
}
