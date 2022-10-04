// Start listening on port 8080 of localhost.
import { serve } from "https://deno.land/std@0.158.0/http/server.ts";
import { config } from "https://deno.land/std@0.158.0/dotenv/mod.ts";

const env = await config();

const port = 8080;

serve(handler, { port });

async function handler(request: Request) {
  const url = new URL(request.url);
  if (url.pathname === "/") {
    const authUrl = new URL(`https://${env.AUTH0_DOMAIN}/authorize`);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set(
      "redirect_uri",
      `http://localhost:${port}/callback`,
    );
    authUrl.searchParams.set("scope", env.AUTH0_SCOPE);
    authUrl.searchParams.set("client_id", env.AUTH0_CLIENT_ID);

    return Response.redirect(authUrl);
  } else if (url.pathname === "/callback") {
    const code = url.searchParams.get("code");
    if (!code) {
      return new Response("Code not set", { status: 500 });
    }

    const body = new URLSearchParams();
    body.set("grant_type", "authorization_code");
    body.set("client_id", env.AUTH0_CLIENT_ID);
    body.set("client_secret", env.AUTH0_CLIENT_SECRET);
    body.set("code", code);
    body.set("redirect_uri", `http://localhost:${port}/callback`);

    const response = await fetch(`https://${env.AUTH0_DOMAIN}/oauth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
    });

    const data = await response.json();
    if (!response.ok) {
      const html = `
      <h1>Error Response</h1>
      <pre>${JSON.stringify(data, null, 2)}</pre>
      <a href="http://localhost:${port}/">Refresh</a>
  `;
      return sendResponse(html, 200);
    }

    const idToken = data.id_token as string;

    const header = JSON.parse(decodeJwt(idToken.split(".")[0]));
    const payload = JSON.parse(decodeJwt(idToken.split(".")[1]));

    const jwtUrl = `https://jwt.io#id_token=${idToken}`;

    const html = `
    <h1>Token Response</h1>
    <pre>${JSON.stringify(data, null, 2)}</pre>
    <h2>Header</h2>
    <pre>${JSON.stringify(header, null, 2)}</pre>
    <h2>Payload</h2>
    <pre>${JSON.stringify(payload, null, 2)}</pre>
    <a href="${jwtUrl}" target="_blank">Inspect with jwt.io</a> | <a href="https://localhost:${port}/">Refresh</a>
`;

    return sendResponse(html, 200);
  }
  return new Response("Not Found", {
    status: 404,
  });
}

function b64DecodeUnicode(str: string) {
  return decodeURIComponent(
    atob(str).replace(/(.)/g, function (m, p) {
      let code = p.charCodeAt(0).toString(16).toUpperCase();
      if (code.length < 2) {
        code = "0" + code;
      }
      return "%" + code;
    }),
  );
}

function decodeJwt(str: string) {
  let output = str.replace(/-/g, "+").replace(/_/g, "/");
  switch (output.length % 4) {
    case 0:
      break;
    case 2:
      output += "==";
      break;
    case 3:
      output += "=";
      break;
    default:
      throw "Illegal base64url string!";
  }

  try {
    return b64DecodeUnicode(output);
  } catch (err) {
    return atob(output);
  }
}

function sendResponse(body: string, status: number) {
  const html = `
  <!doctype html>
  <html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com?plugins=typography"></script>
  </head>
  <body>
    <div class="my-10">
      <div class="prose mx-auto">
        ${body}
      </div>
    </div>
  </body>
  </html>
  `;
  return new Response(html, {
    status,
    headers: {
      "content-type": "text/html",
    },
  });
}
