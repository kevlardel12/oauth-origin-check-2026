"use strict";

const authInput = document.getElementById("auth-url");
const startButton = document.getElementById("start");
const downloadButton = document.getElementById("download");
const resultBox = document.getElementById("result");

let popup = null;
let expectedOrigin = null;
let authorizationEndpoint = null;
let evidence = null;
let complete = false;

function show(message) {
  resultBox.textContent = message;
}

function safeError(message) {
  complete = true;
  startButton.disabled = false;
  authInput.disabled = false;
  show(`Test did not confirm token disclosure. ${message}`);
}

startButton.addEventListener("click", () => {
  let authUrl;
  try {
    authUrl = new URL(authInput.value.trim());
    if (authUrl.protocol !== "https:") throw new Error("HTTPS required");
  } catch (_) {
    show("Enter the exact HTTPS authorization URL from the private report.");
    return;
  }

  complete = false;
  evidence = null;
  downloadButton.disabled = true;
  expectedOrigin = authUrl.origin;
  authorizationEndpoint = `${authUrl.origin}${authUrl.pathname}`;
  show("Opening the real authorization endpoint. Complete consent only with a disposable account.");
  popup = window.open(authUrl.href, "controlled-oauth-origin-check", "width=680,height=760");
  if (!popup) {
    show("The popup was blocked. Allow popups for this page and try again.");
    return;
  }
  startButton.disabled = true;
  authInput.disabled = true;
});

window.addEventListener("message", async (event) => {
  if (complete || !popup || event.source !== popup || event.origin !== expectedOrigin) return;

  if (event.data === "authorizing:github") {
    show(`Live callback handshake received from ${event.origin}. Answering from ${location.origin}.`);
    popup.postMessage("controlled-origin-check", expectedOrigin);
    return;
  }

  if (typeof event.data !== "string") return;
  const prefix = "authorization:github:success:";
  if (!event.data.startsWith(prefix)) {
    if (event.data.startsWith("authorization:github:error:")) {
      safeError("The callback reported an authorization error.");
    }
    return;
  }

  complete = true;
  let payload;
  try {
    payload = JSON.parse(event.data.slice(prefix.length));
  } catch (_) {
    safeError("The callback result was not valid JSON.");
    return;
  }
  let token = typeof payload.token === "string" ? payload.token : "";
  payload.token = "";
  payload = null;
  if (!token) {
    safeError("The callback did not include a token.");
    return;
  }

  const observedAt = new Date().toISOString();
  show(`Token received from the live callback at ${event.origin}. Checking it once with GitHub /user...`);

  let githubStatus = null;
  let githubLogin = null;
  try {
    const response = await fetch("https://api.github.com/user", {
      method: "GET",
      mode: "cors",
      cache: "no-store",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Accept": "application/vnd.github+json"
      }
    });
    token = "";
    githubStatus = response.status;
    if (response.ok) {
      const user = await response.json();
      githubLogin = typeof user.login === "string" ? user.login : null;
    }
  } catch (_) {
    token = "";
  }

  evidence = {
    observed_at_utc: observedAt,
    opener_origin: location.origin,
    authorization_endpoint: authorizationEndpoint,
    callback_origin: event.origin,
    callback_source_matched_popup: true,
    token_received: true,
    github_api_endpoint: "https://api.github.com/user",
    github_http_status: githubStatus,
    github_login: githubLogin,
    token_in_evidence: false
  };

  if (githubStatus === 200 && githubLogin) {
    show(`CONFIRMED IN THIS RUN\nOpener: ${evidence.opener_origin}\nCallback: ${evidence.callback_origin}\nToken received: yes\nGitHub /user: HTTP ${githubStatus}\nDisposable GitHub account: ${githubLogin}\nToken included in result file: no`);
  } else {
    show(`NOT FULLY CONFIRMED IN THIS RUN\nOpener: ${evidence.opener_origin}\nCallback: ${evidence.callback_origin}\nToken received: yes\nGitHub /user: ${githubStatus ?? "request failed"}\nNo successful GitHub identity check was recorded.`);
  }

  downloadButton.disabled = false;
  startButton.disabled = false;
  authInput.disabled = false;
  if (popup && !popup.closed) popup.close();
});

downloadButton.addEventListener("click", () => {
  if (!evidence) return;
  const blob = new Blob([`${JSON.stringify(evidence, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "oauth-live-origin-result.json";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
