import {
  createHash,
  createVerify,
  createPublicKey
} from "crypto";

// ============================================================
// eBay Application Access Token
// ============================================================

async function getEbayApplicationToken_() {

  const clientId =
    String(process.env.EBAY_CLIENT_ID || "").trim();

  const clientSecret =
    String(process.env.EBAY_CLIENT_SECRET || "").trim();


  if (!clientId || !clientSecret) {
    throw new Error(
      "EBAY_CLIENT_ID or EBAY_CLIENT_SECRET is missing"
    );
  }


  const basicAuth =
    Buffer
      .from(`${clientId}:${clientSecret}`)
      .toString("base64");


  const response =
    await fetch(
      "https://api.ebay.com/identity/v1/oauth2/token",
      {
        method: "POST",

        headers: {
          "Authorization": `Basic ${basicAuth}`,
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body:
          "grant_type=client_credentials" +
          "&scope=" +
          encodeURIComponent(
            "https://api.ebay.com/oauth/api_scope"
          )
      }
    );


  const responseText =
    await response.text();


  if (!response.ok) {

    console.error(
      "[eBay message webhook] OAuth HTTP status:",
      response.status
    );

    throw new Error(
      `eBay OAuth failed: HTTP ${response.status}`
    );
  }


  let json;

  try {
    json = JSON.parse(responseText);
  } catch (error) {
    throw new Error(
      "eBay OAuth response was not valid JSON"
    );
  }


  const accessToken =
    String(json?.access_token || "").trim();


  if (!accessToken) {
    throw new Error(
      "eBay OAuth response did not contain access_token"
    );
  }


  console.log(
    "[eBay message webhook] application token acquired: YES"
  );

  console.log(
    "[eBay message webhook] application token expires_in:",
    json?.expires_in || ""
  );


  return accessToken;
}



// ============================================================
// eBay Notification Public Key
// ============================================================

async function getEbayNotificationPublicKey_(
  publicKeyId,
  accessToken
) {

  if (!publicKeyId) {
    throw new Error("publicKeyId is missing");
  }


  const url =
    "https://api.ebay.com/commerce/notification/v1/public_key/" +
    encodeURIComponent(publicKeyId);


  const response =
    await fetch(
      url,
      {
        method: "GET",

        headers: {
          "Authorization":
            `Bearer ${accessToken}`,

          "Accept":
            "application/json"
        }
      }
    );


  const responseText =
    await response.text();


  console.log(
    "[eBay message webhook] Public Key API HTTP status:",
    response.status
  );


  if (!response.ok) {
    throw new Error(
      `Public Key API failed: HTTP ${response.status}`
    );
  }


  let json;

  try {
    json = JSON.parse(responseText);
  } catch (error) {
    throw new Error(
      "Public Key API response was not valid JSON"
    );
  }


  const publicKey =
    String(json?.key || "").trim();


  if (!publicKey) {
    throw new Error(
      "Public Key API response did not contain key"
    );
  }


  console.log(
    "[eBay message webhook] public key acquired: YES"
  );

  console.log(
    "[eBay message webhook] public key length:",
    publicKey.length
  );

  console.log(
    "[eBay message webhook] public key begins correctly:",
    publicKey.startsWith(
      "-----BEGIN PUBLIC KEY-----"
    )
      ? "YES"
      : "NO"
  );

  console.log(
    "[eBay message webhook] public key ends correctly:",
    publicKey.endsWith(
      "-----END PUBLIC KEY-----"
    )
      ? "YES"
      : "NO"
  );


  return {
    publicKey,
    algorithm:
      String(json?.algorithm || ""),
    digest:
      String(json?.digest || "")
  };
}



// ============================================================
// Main Vercel Handler
// ============================================================

export default async function handler(req, res) {

  const proto =
    (req.headers["x-forwarded-proto"] || "https")
      .split(",")[0]
      .trim();

  const host =
    String(req.headers.host || "").trim();

  const path =
    req.url.split("?")[0];

  const absoluteEndpoint =
    `${proto}://${host}${path}`;



  // ==========================================================
  // GET : eBay Destination Challenge
  // ==========================================================

  if (req.method === "GET") {

    const challengeCode =
      req.query?.challenge_code ||
      req.query?.challengeCode ||
      "";


    if (!challengeCode) {

      return res.status(200).json({
        ok: true,
        service:
          "eBay message notification webhook"
      });
    }


    const verificationToken =
      String(
        process.env
          .EBAY_MESSAGE_VERIFICATION_TOKEN ||
        ""
      ).trim();


    if (!verificationToken) {

      console.error(
        "[eBay message webhook] verification token missing"
      );

      return res.status(500).json({
        error:
          "verification token missing"
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


    return res.status(200).json({
      challengeResponse
    });
  }



  // ==========================================================
  // HEAD / OPTIONS
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
  // POST
  // ==========================================================

  if (req.method === "POST") {

    console.log(
      "========================================"
    );

    console.log(
      "[eBay message webhook] POST received"
    );


    // --------------------------------------------------------
    // Environment Variables
    // --------------------------------------------------------

    const clientId =
      String(
        process.env.EBAY_CLIENT_ID || ""
      ).trim();

    const clientSecret =
      String(
        process.env.EBAY_CLIENT_SECRET || ""
      ).trim();


    console.log(
      "[eBay message webhook] clientId present:",
      clientId ? "YES" : "NO"
    );

    console.log(
      "[eBay message webhook] clientSecret present:",
      clientSecret ? "YES" : "NO"
    );


    if (
      !clientId ||
      !clientSecret
    ) {

      console.error(
        "[eBay message webhook] client credentials missing"
      );

      return res.status(500).json({
        received: false
      });
    }



    // --------------------------------------------------------
    // X-EBAY-SIGNATURE
    // --------------------------------------------------------

    const ebaySignature =
      String(
        req.headers[
          "x-ebay-signature"
        ] || ""
      ).trim();


    console.log(
      "[eBay message webhook] X-EBAY-SIGNATURE present:",
      ebaySignature ? "YES" : "NO"
    );


    if (!ebaySignature) {

      console.error(
        "[eBay message webhook] signature missing"
      );

      return res.status(412).json({
        received: false
      });
    }



    // --------------------------------------------------------
    // Decode signature header
    // --------------------------------------------------------

    let signatureMetadata;


    try {

      const decodedText =
        Buffer
          .from(
            ebaySignature,
            "base64"
          )
          .toString("utf8");


      signatureMetadata =
        JSON.parse(decodedText);


    } catch (error) {

      console.error(
        "[eBay message webhook] signature decode failed:",
        error?.message ||
        String(error)
      );


      return res.status(412).json({
        received: false
      });
    }



    const algorithm =
      String(
        signatureMetadata?.alg || ""
      ).trim();

    const digest =
      String(
        signatureMetadata?.digest || ""
      ).trim();

    const publicKeyId =
      String(
        signatureMetadata?.kid || ""
      ).trim();

    const signatureBody =
      String(
        signatureMetadata?.signature || ""
      ).trim();



    console.log(
      "[eBay message webhook] signature decoded: YES"
    );

    console.log(
      "[eBay message webhook] signature alg:",
      algorithm
    );

    console.log(
      "[eBay message webhook] signature digest:",
      digest
    );

    console.log(
      "[eBay message webhook] signature kid:",
      publicKeyId
    );

    console.log(
      "[eBay message webhook] signature body present:",
      signatureBody
        ? "YES"
        : "NO"
    );

    // --------------------------------------------------------
// Signature binary inspection
// 秘密情報そのものはログに出さない
// --------------------------------------------------------

let signatureBuffer;

try {

  signatureBuffer =
    Buffer.from(
      signatureBody,
      "base64"
    );

  console.log(
    "[eBay message webhook] signature base64 length:",
    signatureBody.length
  );

  console.log(
    "[eBay message webhook] signature decoded bytes:",
    signatureBuffer.length
  );

  console.log(
    "[eBay message webhook] signature first byte:",
    signatureBuffer.length
      ? `0x${signatureBuffer[0].toString(16).padStart(2, "0")}`
      : ""
  );

  console.log(
    "[eBay message webhook] signature looks DER:",
    signatureBuffer.length &&
    signatureBuffer[0] === 0x30
      ? "YES"
      : "NO"
  );

} catch (error) {

  console.error(
    "[eBay message webhook] signature binary decode failed:",
    error?.message || String(error)
  );

  return res.status(412).json({
    received: false
  });
}

    if (
      !publicKeyId ||
      !signatureBody
    ) {

      console.error(
        "[eBay message webhook] incomplete signature metadata"
      );

      return res.status(412).json({
        received: false
      });
    }



    // --------------------------------------------------------
    // Payload inspection
    // --------------------------------------------------------

    let payload =
      req.body;


    if (
      typeof payload === "string"
    ) {

      try {

        payload =
          JSON.parse(payload);

      } catch (error) {

        console.error(
          "[eBay message webhook] payload JSON parse failed"
        );

        return res.status(400).json({
          received: false
        });
      }
    }



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
      "[eBay message webhook] notificationId:",
      notification?.notificationId || ""
    );

    console.log(
      "[eBay message webhook] messageId:",
      data?.messageId || ""
    );

    console.log(
      "[eBay message webhook] listingId:",
      data?.listingId || ""
    );



    // --------------------------------------------------------
    // OAuth Application Token
    // --------------------------------------------------------

    let accessToken;


    try {

      accessToken =
        await getEbayApplicationToken_();

    } catch (error) {

      console.error(
        "[eBay message webhook] OAuth failed:",
        error?.message ||
        String(error)
      );


      console.log(
        "[eBay message webhook] no data saved"
      );


      return res.status(500).json({
        received: false
      });
    }



    // --------------------------------------------------------
    // Public Key API
    // --------------------------------------------------------

    let publicKeyResult;


    try {

      publicKeyResult =
        await getEbayNotificationPublicKey_(
          publicKeyId,
          accessToken
        );

    } catch (error) {

      console.error(
        "[eBay message webhook] Public Key retrieval failed:",
        error?.message ||
        String(error)
      );


      console.log(
        "[eBay message webhook] no data saved"
      );


      return res.status(500).json({
        received: false
      });
    }

    // --------------------------------------------------------
    // Public Key format diagnostics
    // 公開鍵そのものはログに出さない
    // --------------------------------------------------------

    try {

      const publicKeyText =
        String(
          publicKeyResult.publicKey || ""
        );

      const hasRealLf =
        publicKeyText.includes("\n");

      const hasRealCr =
        publicKeyText.includes("\r");

      const hasLiteralBackslashN =
        publicKeyText.includes("\\n");

      const publicKeyLines =
        publicKeyText.split(/\r?\n/);

      console.log(
        "[eBay message webhook] public key real LF:",
        hasRealLf ? "YES" : "NO"
      );

      console.log(
        "[eBay message webhook] public key real CR:",
        hasRealCr ? "YES" : "NO"
      );

      console.log(
        "[eBay message webhook] public key literal \\\\n:",
        hasLiteralBackslashN ? "YES" : "NO"
      );

      console.log(
        "[eBay message webhook] public key line count:",
        publicKeyLines.length
      );

      console.log(
        "[eBay message webhook] public key line lengths:",
        publicKeyLines
          .map(line => line.length)
          .join(",")
      );


      const publicKeyBase64 =
        publicKeyText
          .replace(
            "-----BEGIN PUBLIC KEY-----",
            ""
          )
          .replace(
            "-----END PUBLIC KEY-----",
            ""
          )
          .replace(/\s/g, "");


      const publicKeyDer =
        Buffer.from(
          publicKeyBase64,
          "base64"
        );


      console.log(
        "[eBay message webhook] public key base64 body length:",
        publicKeyBase64.length
      );

      console.log(
        "[eBay message webhook] public key DER bytes:",
        publicKeyDer.length
      );

      console.log(
        "[eBay message webhook] public key DER first byte:",
        publicKeyDer.length
          ? `0x${publicKeyDer[0]
              .toString(16)
              .padStart(2, "0")}`
          : ""
      );


      try {

        const keyObject =
          createPublicKey(
            publicKeyText
          );

        console.log(
          "[eBay message webhook] createPublicKey PEM:",
          "SUCCESS"
        );

        console.log(
          "[eBay message webhook] key type:",
          keyObject.type || ""
        );

        console.log(
          "[eBay message webhook] asymmetric key type:",
          keyObject.asymmetricKeyType || ""
        );

      } catch (pemError) {

        console.log(
          "[eBay message webhook] createPublicKey PEM:",
          "FAILED"
        );

        console.log(
          "[eBay message webhook] createPublicKey PEM error:",
          pemError?.message ||
          String(pemError)
        );
      }


      try {

        const derKeyObject =
          createPublicKey({
            key: publicKeyDer,
            format: "der",
            type: "spki"
          });

        console.log(
          "[eBay message webhook] createPublicKey DER/SPKI:",
          "SUCCESS"
        );

        console.log(
          "[eBay message webhook] DER/SPKI key type:",
          derKeyObject.type || ""
        );

        console.log(
          "[eBay message webhook] DER/SPKI asymmetric key type:",
          derKeyObject.asymmetricKeyType || ""
        );

      } catch (derError) {

        console.log(
          "[eBay message webhook] createPublicKey DER/SPKI:",
          "FAILED"
        );

        console.log(
          "[eBay message webhook] createPublicKey DER/SPKI error:",
          derError?.message ||
          String(derError)
        );
      }


    } catch (diagnosticError) {

      console.log(
        "[eBay message webhook] public key diagnostic error:",
        diagnosticError?.message ||
        String(diagnosticError)
      );
    }

    // --------------------------------------------------------
    // Compare metadata only
    // --------------------------------------------------------

    console.log(
      "[eBay message webhook] Public Key API algorithm:",
      publicKeyResult.algorithm
    );

    console.log(
      "[eBay message webhook] Public Key API digest:",
      publicKeyResult.digest
    );


    console.log(
      "[eBay message webhook] algorithm matches:",
      algorithm.toLowerCase() ===
      publicKeyResult.algorithm.toLowerCase()
        ? "YES"
        : "NO"
    );


    console.log(
      "[eBay message webhook] digest matches:",
      digest.toLowerCase() ===
      publicKeyResult.digest.toLowerCase()
        ? "YES"
        : "NO"
    );



        // ========================================================
    // eBay Notification Signature Verification
    // ========================================================

    let signatureVerified = false;

    try {

      // eBay公式SDKと同じ方式で、
      // 受信した通知JSONを署名検証対象にする
      const signedMessage =
        JSON.stringify(payload);

      const verifier =
        createVerify("SHA1");

      verifier.update(
        signedMessage,
        "utf8"
      );

      verifier.end();

      signatureVerified =
        verifier.verify(
          publicKeyResult.publicKey,
          signatureBody,
          "base64"
        );


      console.log(
        "[eBay message webhook] signature verification:",
        signatureVerified
          ? "VALID"
          : "INVALID"
      );


    } catch (error) {

      console.error(
        "[eBay message webhook] signature verification error:",
        error?.message ||
        String(error)
      );

      console.log(
        "[eBay message webhook] no data saved"
      );

      console.log(
        "========================================"
      );

      return res.status(412).json({
        received: false,
        publicKeyRetrieved: true,
        signatureVerified: false
      });
    }



    // ========================================================
    // Signature INVALID
    // ========================================================

    if (!signatureVerified) {

      console.error(
        "[eBay message webhook] SIGNATURE INVALID"
      );

      console.log(
        "[eBay message webhook] no data saved"
      );

      console.log(
        "========================================"
      );

      return res.status(412).json({
        received: false,
        publicKeyRetrieved: true,
        signatureVerified: false
      });
    }



    // ========================================================
    // Signature VALID
    // ========================================================

    console.log(
      "[eBay message webhook] SIGNATURE VALID"
    );

    console.log(
      "[eBay message webhook] no data saved"
    );

    console.log(
      "========================================"
    );


    return res.status(200).json({
      received: true,
      publicKeyRetrieved: true,
      signatureVerified: true
    });
    
 }


  // ==========================================================
  // Other Methods
  // ==========================================================

  return res.status(405).json({
    error: "Method Not Allowed"
  });
}
