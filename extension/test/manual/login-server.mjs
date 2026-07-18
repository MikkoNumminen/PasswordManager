// Manual test server for the extension's autofill and save flows. Zero
// dependencies; run with `node extension/test/manual/login-server.mjs` and
// open http://127.0.0.1:8099. Deliberately not named *.test.* so node's test
// runner never picks it up.
//
// Pages:
//   /          classic login form; POST /login -> 303 -> /welcome
//   /spa       fetch()-based login, no navigation (SPA fallback banner)
//   /change    change-password form, three password fields (must be ignored)
//   /twoforms  a search form plus a login form (anchoring precision)

import http from "node:http";

const page = (title, body) => `<!doctype html>
<html><head><meta charset="utf-8"><title>${title}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 460px; margin: 3rem auto; }
  label { display: block; margin-top: 1rem; }
  input { width: 100%; padding: 8px; font-size: 1rem; box-sizing: border-box; }
  button { margin-top: 1rem; padding: 8px 16px; }
  nav a { margin-right: 1rem; }
</style></head>
<body>
<nav><a href="/">login</a><a href="/spa">spa</a><a href="/change">change</a><a href="/twoforms">two forms</a></nav>
${body}
</body></html>`;

const loginForm = `
<h1>Sign in</h1>
<form method="post" action="/login">
  <label>Username <input type="text" name="username" autocomplete="username"></label>
  <label>Password <input type="password" name="password" autocomplete="current-password"></label>
  <button type="submit">Sign in</button>
</form>`;

const routes = {
  "GET /": page("Login", loginForm),
  "GET /welcome": page("Welcome", `<h1>Logged in</h1><p>No password fields here; the save banner should appear on this page.</p>`),
  "GET /spa": page(
    "SPA login",
    `<h1>SPA sign in</h1>
    <form id="f">
      <label>Username <input type="text" name="username"></label>
      <label>Password <input type="password" name="password"></label>
      <button type="submit">Sign in</button>
    </form>
    <script>
      document.getElementById("f").addEventListener("submit", async (e) => {
        e.preventDefault();
        await fetch("/login", { method: "POST" });
        document.getElementById("f").outerHTML = "<p>Logged in without navigating; the banner should appear here within ~4 s.</p>";
      });
    </script>`
  ),
  "GET /change": page(
    "Change password",
    `<h1>Change password</h1>
    <form method="post" action="/login">
      <label>Current password <input type="password" name="old"></label>
      <label>New password <input type="password" name="new" autocomplete="new-password"></label>
      <label>Confirm new password <input type="password" name="confirm" autocomplete="new-password"></label>
      <button type="submit">Change</button>
    </form>
    <p>Three password fields: the extension must offer nothing here.</p>`
  ),
  "GET /twoforms": page(
    "Two forms",
    `<h1>Search and sign in</h1>
    <form method="get" action="/twoforms">
      <label>Search <input type="text" name="q"></label>
      <button type="submit">Search</button>
    </form>
    <hr>
    ${loginForm}`
  ),
};

http
  .createServer((req, res) => {
    if (req.method === "POST" && req.url === "/login") {
      // Swallow the body and bounce to the logged-in page.
      req.resume();
      req.on("end", () => {
        res.writeHead(303, { location: "/welcome" });
        res.end();
      });
      return;
    }
    const body = routes[`${req.method} ${req.url}`];
    if (!body) {
      res.writeHead(404);
      res.end("not found");
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(body);
  })
  .listen(8099, "127.0.0.1", () => {
    console.log("manual test server: http://127.0.0.1:8099");
  });
