import { serve } from "https://deno.land/std@0.114.0/http/server.ts";
import { corsHeaders } from "../_shared/cors.ts";

console.log("Function 'check-availability' up and running!");

// Helper function to base64Url encode a string
function base64UrlEncode(input: string): string {
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// Function to create a JWT manually
async function createJWT(payload: Record<string, unknown>, privateKey: string): Promise<string> {
  console.log("[Step] Creating JWT...");
  const header = {
    alg: "RS256",
    typ: "JWT",
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));

  const unsignedToken = `${encodedHeader}.${encodedPayload}`;

  console.log("[Step] Converting PEM to ArrayBuffer...");
  const privateKeyBuffer = pemToArrayBuffer(privateKey);

  // Import the key for signing
  let cryptoKey;
  try {
    console.log("[Step] Importing private key for signing...");
    cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      privateKeyBuffer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      },
      false,
      ["sign"],
    );
  } catch (importError) {
    console.error("Error importing private key:", importError);
    throw new Error("Failed to import private key");
  }

  // Sign the token
  let signature;
  try {
    console.log("[Step] Signing JWT...");
    signature = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      cryptoKey,
      new TextEncoder().encode(unsignedToken),
    );
  } catch (signError) {
    console.error("Error signing JWT:", signError);
    throw new Error("Failed to sign JWT");
  }

  const encodedSignature = base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
  console.log("[Step] JWT Created Successfully");

  return `${unsignedToken}.${encodedSignature}`;
}

// Function to convert PEM to ArrayBuffer
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  pem = pem.replace(pemHeader, "").replace(pemFooter, "").replace(/\s+/g, "");

  const binaryString = atob(pem);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Serve function
serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: { 
      ...corsHeaders,
      "Access-Control-Allow-Origin": "*",
      "Content-Type": "application/json", 
    } });
  }

  try {
    console.log("[Step] Retrieving environment variable: SERVICE_ACCOUNT_CREDENTIALS");
    const SERVICE_ACCOUNT_CREDENTIALS = Deno.env.get("SERVICE_ACCOUNT_CREDENTIALS");
    if (!SERVICE_ACCOUNT_CREDENTIALS) {
      console.error("[Error] SERVICE_ACCOUNT_CREDENTIALS environment variable is not found.");
      throw new Error("Missing SERVICE_ACCOUNT_CREDENTIALS environment variable");
    }

    console.log("[Step] SERVICE_ACCOUNT_CREDENTIALS successfully retrieved.");

    let credentials;
    try {
      console.log("[Step] Parsing SERVICE_ACCOUNT_CREDENTIALS...");
      credentials = JSON.parse(SERVICE_ACCOUNT_CREDENTIALS);
      console.log("[Step] SERVICE_ACCOUNT_CREDENTIALS parsed successfully.");
    } catch (parseError) {
      console.error("Failed to parse SERVICE_ACCOUNT_CREDENTIALS:", parseError);
      throw new Error("Invalid JSON format in SERVICE_ACCOUNT_CREDENTIALS");
    }

    const { client_email, private_key } = credentials;

    if (!client_email || !private_key) {
      throw new Error("Invalid or missing credentials in SERVICE_ACCOUNT_CREDENTIALS");
    }

    console.log("[Step] Creating JWT...");
    const jwt = await createJWT({
      iss: client_email,
      scope: "https://www.googleapis.com/auth/calendar.readonly",
      aud: "https://oauth2.googleapis.com/token",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    }, private_key);
    console.log("[Step] JWT Created Successfully");

    console.log("[Step] Requesting access token...");
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: jwt,
      }),
    });

    const tokenText = await tokenResponse.text();
    console.log("[Step] Token response text:", tokenText); // Log the raw response for inspection

    if (!tokenResponse.ok) {
      console.error("Error response from Google OAuth token endpoint:", tokenText);
      throw new Error(`Failed to fetch access token. Status: ${tokenResponse.status}`);
    }

    const tokenData = JSON.parse(tokenText);
    const accessToken = tokenData.access_token;
    console.log("[Step] Access Token Obtained Successfully");

    if (!accessToken) {
      throw new Error("Access token is null or undefined. Unable to proceed.");
    }

    // Use the access token to fetch calendar events
    console.log("[Step] Fetching calendar events...");
    const calendarId = 'ethuxdesigns@gmail.com';
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const timeMin = today.toISOString();

    const oneWeekFromToday = new Date(today.getTime() + 7 * 24 * 60 * 60 * 1000);
    oneWeekFromToday.setHours(23, 59, 59, 999);
    const timeMax = oneWeekFromToday.toISOString();

    console.log("[Step] Accessing Google Calendar API with access token...");
    console.log("Request Details - Calendar ID:", calendarId);
    console.log("Request Details - Time Range:", `From ${timeMin} to ${timeMax}`);

    const calendarResponse = await fetch(
      `https://www.googleapis.com/calendar/v3/calendars/${calendarId}/events?timeMin=${timeMin}&timeMax=${timeMax}&singleEvents=true&orderBy=startTime`,
      {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/json',
        },
      }
    );

    if (!calendarResponse.ok) {
      throw new Error(`Failed to fetch calendar events. Status: ${calendarResponse.status}`);
    }

    const calendarData = await calendarResponse.json();

    if (!calendarData || !calendarData.items || !Array.isArray(calendarData.items)) {
      throw new Error('Unexpected response format from Google Calendar API: missing or invalid items.');
    }

    const events = calendarData.items.map((event: any) => {
      return {
        title: event.summary ?? 'No title provided',
        start: event.start?.dateTime ?? event.start?.date ?? 'No start time provided',
        end: event.end?.dateTime ?? event.end?.date ?? 'No end time provided',
        link: event.htmlLink ?? 'No link available',
      };
    });

    console.log('Available events:', JSON.stringify(events, null, 2));

    return new Response(JSON.stringify(events), {
      status: 200,
      headers: {
        ...corsHeaders,
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json",
      },
    });

  } catch (error: unknown) {
    console.error("Error during the process:", error);
    return new Response(JSON.stringify({ error: (error as Error).message }), {
      status: 500,
      headers: {
        ...corsHeaders,
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json",
      },
    });
  }
});
