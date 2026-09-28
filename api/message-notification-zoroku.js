import {
  createHash,
  createVerify
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


  return {
    publicKey,

    algorithm:
      String(json?.algorithm || "").trim(),

    digest:
      String(json?.digest || "").trim()
  };
}


// ============================================================
// eBay Public Key → SDK-compatible PEM
// ============================================================

function normalizeEbayPublicKey_(publicKey) {

  const value =
    String(publicKey || "").trim();


  if (!value) {
    throw new Error(
      "eBay public key is empty"
    );
  }


  /*
   * eBay Public Key API currently returns the PEM material
   * without line breaks around the base64 body.
   *
   * Convert it to the same usable PEM structure that was
   * confirmed against real eBay notifications.
   */

  const normalized =
    value
      .replace(
        "-----BEGIN PUBLIC KEY-----",
        "-----BEGIN PUBLIC KEY-----\n"
      )
      .replace(
        "-----END PUBLIC KEY-----",
        "\n-----END PUBLIC KEY-----"
      );


  if (
    !normalized.includes(
      "-----BEGIN PUBLIC KEY-----"
    ) ||
    !normalized.includes(
      "-----END PUBLIC KEY-----"
    )
  ) {
    throw new Error(
      "eBay public key PEM format is invalid"
    );
  }


  return normalized;
}


// ============================================================
// eBay Notification Signature Verification
// ============================================================

function verifyEbayNotificationSignature_(
  payload,
  signatureBody,
  publicKey
) {

  if (
    !payload ||
    typeof payload !== "object"
  ) {
    throw new Error(
      "notification payload is invalid"
    );
  }


  if (!signatureBody) {
    throw new Error(
      "signature body is missing"
    );
  }


  const normalizedPublicKey =
    normalizeEbayPublicKey_(publicKey);


  /*
   * This is the verification target confirmed with real
   * BUYER_QUESTION and NEW_MESSAGE notifications.
   *
   * Do not verify notification/data separately.
   */

  const verificationTarget =
    JSON.stringify(payload);


  const verifier =
    createVerify("ssl3-sha1");


  verifier.update(
    verificationTarget,
    "utf8"
  );

  verifier.end();


  return verifier.verify(
    normalizedPublicKey,
    signatureBody,
    "base64"
  );
}


// ============================================================
// GAS Notification Ingest
// ============================================================

async function forwardVerifiedNotificationToGas_(payload) {

  const gasUrl =
    String(
      process.env.EBAY_NOTIFICATION_GAS_URL || ""
    ).trim();

  const ingestSecret =
    String(
      process.env.EBAY_NOTIFICATION_INGEST_SECRET || ""
    ).trim();


  if (!gasUrl || !ingestSecret) {
    throw new Error(
      "EBAY_NOTIFICATION_GAS_URL or EBAY_NOTIFICATION_INGEST_SECRET is missing"
    );
  }


  const metadata =
    payload?.metadata || {};

  const notification =
    payload?.notification || {};

  const data =
    notification?.data || {};


  const body = {
    secret:
      ingestSecret,

    account_name:
      "zorokuharico",

    topic:
      String(metadata?.topic || "").trim(),

    notification_id:
      String(
        notification?.notificationId || ""
      ).trim(),

    message_id:
      String(data?.messageId || "").trim(),

    listing_id:
      String(data?.listingId || "").trim(),

    conversation_id:
      String(
        data?.conversationId || ""
      ).trim(),

    conversation_type:
      String(
        data?.conversationType || ""
      ).trim(),

    sender_username:
      String(
        data?.senderUserName || ""
      ).trim(),

    recipient_username:
      String(
        data?.recipientUserName || ""
      ).trim(),

    subject:
      String(data?.subject || "").trim(),

    message_body:
      String(data?.messageBody || ""),

    read_status:
      String(data?.readStatus || "").trim(),

    created_date:
      String(data?.createdDate || "").trim()
  };


  const response =
    await fetch(
      gasUrl,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json"
        },

        body:
          JSON.stringify(body),

        redirect:
          "follow"
      }
    );


  const responseText =
    await response.text();


  console.log(
    "[eBay message webhook] GAS HTTP status:",
    response.status
  );


  if (!response.ok) {
    throw new Error(
      `GAS ingest failed: HTTP ${response.status}`
    );
  }


  let result;

  try {
    result =
      JSON.parse(responseText);
  } catch (error) {
    throw new Error(
      "GAS ingest response was not valid JSON"
    );
  }


  if (!result?.ok) {
    throw new Error(
      `GAS ingest rejected: ${String(
        result?.error || "unknown_error"
      )}`
    );
  }


  console.log(
    "[eBay message webhook] GAS ingest:",
    result?.duplicate
      ? "DUPLICATE"
      : "SAVED"
  );


  return result;
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


    if (
      !clientId ||
      !clientSecret
    ) {

      console.error(
        "[eBay message webhook] client credentials missing"
      );

      console.log(
        "[eBay message webhook] no data saved"
      );

      console.log(
        "========================================"
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

      console.log(
        "[eBay message webhook] no data saved"
      );

      console.log(
        "========================================"
      );

      return res.status(412).json({
        received: false,
        signatureVerified: false
      });
    }


    // --------------------------------------------------------
    // Decode X-EBAY-SIGNATURE
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

      console.log(
        "[eBay message webhook] no data saved"
      );

      console.log(
        "========================================"
      );

      return res.status(412).json({
        received: false,
        signatureVerified: false
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


    if (
      !publicKeyId ||
      !signatureBody
    ) {

      console.error(
        "[eBay message webhook] incomplete signature metadata"
      );

      console.log(
        "[eBay message webhook] no data saved"
      );

      console.log(
        "========================================"
      );

      return res.status(412).json({
        received: false,
        signatureVerified: false
      });
    }


    // --------------------------------------------------------
    // Payload
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

        console.log(
          "[eBay message webhook] no data saved"
        );

        console.log(
          "========================================"
        );

        return res.status(400).json({
          received: false
        });
      }
    }


    if (
      !payload ||
      typeof payload !== "object"
    ) {

      console.error(
        "[eBay message webhook] payload is invalid"
      );

      console.log(
        "[eBay message webhook] no data saved"
      );

      console.log(
        "========================================"
      );

      return res.status(400).json({
        received: false
      });
    }


    const metadata =
      payload?.metadata || {};

    const notification =
      payload?.notification || {};

    const data =
      notification?.data || {};


    const topic =
      String(
        metadata?.topic || ""
      ).trim();

    const notificationId =
      String(
        notification?.notificationId || ""
      ).trim();

    const messageId =
      String(
        data?.messageId || ""
      ).trim();

    const listingId =
      String(
        data?.listingId || ""
      ).trim();


    console.log(
      "[eBay message webhook] topic:",
      topic
    );

    console.log(
      "[eBay message webhook] notificationId:",
      notificationId
    );

    console.log(
      "[eBay message webhook] messageId:",
      messageId
    );

    console.log(
      "[eBay message webhook] listingId:",
      listingId
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

      console.log(
        "========================================"
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

      console.log(
        "========================================"
      );

      return res.status(500).json({
        received: false
      });
    }


    // --------------------------------------------------------
    // Metadata consistency check
    // --------------------------------------------------------

    const algorithmMatches =
      algorithm.toLowerCase() ===
      publicKeyResult.algorithm.toLowerCase();

    const digestMatches =
      digest.toLowerCase() ===
      publicKeyResult.digest.toLowerCase();


    console.log(
      "[eBay message webhook] algorithm matches:",
      algorithmMatches
        ? "YES"
        : "NO"
    );

    console.log(
      "[eBay message webhook] digest matches:",
      digestMatches
        ? "YES"
        : "NO"
    );


    if (
      !algorithmMatches ||
      !digestMatches
    ) {

      console.error(
        "[eBay message webhook] signature metadata mismatch"
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
    // eBay Notification Signature Verification
    // ========================================================

    let signatureVerified = false;


    try {

      signatureVerified =
        verifyEbayNotificationSignature_(
          payload,
          signatureBody,
          publicKeyResult.publicKey
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


    console.log(
      "[eBay message webhook] signature verification:",
      signatureVerified
        ? "VALID"
        : "INVALID"
    );


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
      "[eBay message webhook] verified topic:",
      topic
    );

    console.log(
      "[eBay message webhook] verified messageId:",
      messageId
    );

    console.log(
      "[eBay message webhook] verified listingId:",
      listingId
    );


    // ========================================================
    // Forward verified notification to GAS
    // ========================================================

    let gasResult;


    try {

      gasResult =
        await forwardVerifiedNotificationToGas_(
          payload
        );

    } catch (error) {

      console.error(
        "[eBay message webhook] GAS ingest failed:",
        error?.message ||
        String(error)
      );

      console.log(
        "[eBay message webhook] notification not confirmed"
      );

      console.log(
        "========================================"
      );

      return res.status(500).json({
        received: false,
        topic,
        notificationId,
        messageId,
        listingId,
        publicKeyRetrieved: true,
        signatureVerified: true,
        gasSaved: false
      });
    }


    console.log(
      "[eBay message webhook] GAS ingest confirmed"
    );

    console.log(
      "========================================"
    );


    return res.status(200).json({
      received: true,
      topic,
      notificationId,
      messageId,
      listingId,
      publicKeyRetrieved: true,
      signatureVerified: true,
      gasSaved:
        Boolean(gasResult?.saved),
      gasDuplicate:
        Boolean(gasResult?.duplicate)
    });
  }


  // ==========================================================
  // Other Methods
  // ==========================================================

  return res.status(405).json({
    error: "Method Not Allowed"
  });
}
