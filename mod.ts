// Start listening on port 8080 of localhost.
import { serve } from "https://deno.land/std@0.158.0/http/server.ts";
import { config } from "https://deno.land/std@0.158.0/dotenv/mod.ts";
import {
  RouteHandler,
  Router,
} from "https://deno.land/x/tinyrouter@1.1.0/mod.ts";

interface Env {
  AUTH0_DOMAIN: string;
  AUTH0_CLIENT_ID: string;
  AUTH0_CLIENT_SECRET: string;
  AUTH0_SCOPE: string;
  AUDIENCE: string;
  BASE_URL: string;
}

const env = (await config()) as unknown as Env;

const port = 8080;

const authorize: RouteHandler = (request) => {
  const authUrl = new URL(`https://${env.AUTH0_DOMAIN}/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", `${env.BASE_URL}/callback`);
  authUrl.searchParams.set("scope", env.AUTH0_SCOPE);
  authUrl.searchParams.set("client_id", env.AUTH0_CLIENT_ID);
  if (env.AUDIENCE) {
    authUrl.searchParams.set("audience", env.AUDIENCE);
  }

  return Response.redirect(authUrl);
};

const logout: RouteHandler = (request) => {
  return Response.redirect(
    `https://${env.AUTH0_DOMAIN}/v2/logout?federated&returnTo=${encodeURI(
      env.BASE_URL
    )}`
  );
};

const callback: RouteHandler = async (request) => {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  if (!code) {
    return new Response("Code not set", { status: 500 });
  }

  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("client_id", env.AUTH0_CLIENT_ID);
  body.set("client_secret", env.AUTH0_CLIENT_SECRET);
  body.set("code", code);
  body.set("redirect_uri", `${env.BASE_URL}/callback`);

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
      <a href="${env.BASE_URL}/logout">Logout</a>
      <pre>${JSON.stringify(data, null, 2)}</pre>
  `;
    return sendResponse(html, 200);
  }

  const idToken: string | undefined = data.id_token;
  const accessToken: string | undefined = data.access_token;
  const refreshToken: string | undefined = data.refresh_token;

  let html = `
    <h1>Authentication Result</h1>
    <a href="${env.BASE_URL}/logout">Logout</a>
    <h2>Token Response</h2>
    <pre>${JSON.stringify(data, null, 2)}</pre>`;

  // Get Profile
  if (accessToken) {
    const profile = await getProfile(accessToken);
    html += `
      <hr/>
      <h2>Profile</h2>
      <pre>${JSON.stringify(profile, null, 2)}</pre>
      `;
  }

  if (idToken) {
    html += getTokenHtml("ID Token", idToken);
  }

  if (accessToken && !accessToken.includes("..")) {
    html += getTokenHtml("Access Token", accessToken);
  }

  if (refreshToken) {
    html += getRefreshHtml(refreshToken);
  }

  return sendResponse(html, 200);
};

const router = new Router();
router.get("/", authorize);
router.get("/logout", logout);
router.get("/callback", callback);
router.all("*", () => new Response("Not found", { status: 404 }));

serve((request) => router.handler(request), { port });

function getTokenHtml(tokenName: string, token: string) {
  const header = JSON.parse(decodeJwt(token.split(".")[0]));
  const payload = JSON.parse(decodeJwt(token.split(".")[1]));

  const jwtUrl = `https://jwt.io#id_token=${token}`;

  return `
<hr />
<h2>${tokenName}</h2>
<h3>Header</h3>
<pre>${JSON.stringify(header, null, 2)}</pre>
<h3>Payload</h3>
<pre>${JSON.stringify(payload, null, 2)}</pre>
<a href="${jwtUrl}" target="_blank">Inspect with jwt.io</a>
`;
}

function getRefreshHtml(refreshToken: string) {
  return `
  <hr />
  <h2>Refresh Token Request</h2>
  <pre>
  curl --request POST \\
    --url 'https://${env.AUTH0_DOMAIN}/oauth/token' \\
    --header 'content-type: application/x-www-form-urlencoded' \\
    --data grant_type=refresh_token \\
    --data 'client_id=${env.AUTH0_CLIENT_ID}' \\
    --data 'client_secret=${env.AUTH0_CLIENT_SECRET}' \\
    --data 'refresh_token=${refreshToken}'
  </pre>
  `;
}

async function getProfile(accessToken: string) {
  if (!env.AUTH0_SCOPE?.includes("oidc")) {
    return {};
  }
  const response = await fetch(`https://${env.AUTH0_DOMAIN}/userinfo`, {
    headers: {
      authorization: `Bearer ${accessToken}`,
    },
  });
  if (!response.ok) {
    throw new Error("cannot get profile");
  }
  const data = await response.json();
  return data;
}

function b64DecodeUnicode(str: string) {
  return decodeURIComponent(
    atob(str).replace(/(.)/g, function (m, p) {
      let code = p.charCodeAt(0).toString(16).toUpperCase();
      if (code.length < 2) {
        code = "0" + code;
      }
      return "%" + code;
    })
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
