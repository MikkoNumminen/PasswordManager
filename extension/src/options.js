// Options: store the server URL and API token, and request host permission
// for that one origin at save time (never a broad standing grant).

const $ = (id) => document.getElementById(id);

async function load() {
  const c = await chrome.storage.local.get(["serverUrl", "token", "autoLockMinutes"]);
  $("url").value = c.serverUrl || "";
  $("token").value = c.token || "";
  $("autolock").value = String(c.autoLockMinutes ?? 15);
}

function setStatus(text, cls) {
  const el = $("status");
  el.textContent = text;
  el.className = cls || "muted";
}

$("save").addEventListener("click", async () => {
  const raw = $("url").value.trim();
  let origin;
  try {
    origin = new URL(raw).origin;
  } catch {
    setStatus("That is not a valid URL.", "error");
    return;
  }
  const token = $("token").value.trim();
  if (!token) {
    setStatus("Enter the API token.", "error");
    return;
  }

  // Ask for access to this one origin, at this user gesture.
  const granted = await chrome.permissions.request({ origins: [origin + "/*"] });
  if (!granted) {
    setStatus("Permission for that origin was declined; the extension cannot reach it.", "error");
    return;
  }

  await chrome.storage.local.set({
    serverUrl: raw.replace(/\/$/, ""),
    token,
    autoLockMinutes: Number($("autolock").value),
  });
  setStatus("Saved.", "ok");
});

load();
