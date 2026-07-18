// Options: store the server URL and API token, and request host permission
// for that one origin at save time (never a broad standing grant).

const $ = (id) => document.getElementById(id);

async function load() {
  const c = await chrome.storage.local.get(["serverUrl", "token", "autoLockMinutes"]);
  $("url").value = c.serverUrl || "";
  $("token").value = c.token || "";
  $("autolock").value = String(c.autoLockMinutes ?? 15);
  await renderNeverList();
}

// Sites where the save banner is suppressed ("Never for this site").
async function renderNeverList() {
  const { neverSaveDomains } = await chrome.storage.local.get("neverSaveDomains");
  const list = neverSaveDomains || [];
  const ul = $("never-list");
  ul.replaceChildren();
  if (!list.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "none";
    ul.appendChild(li);
    return;
  }
  for (const domain of list) {
    const li = document.createElement("li");
    li.style.cssText = "display:flex; justify-content:space-between; align-items:center; padding:0.3rem 0;";
    const span = document.createElement("span");
    span.textContent = domain;
    const rm = document.createElement("button");
    rm.textContent = "remove";
    rm.style.marginTop = "0";
    rm.addEventListener("click", async () => {
      const { neverSaveDomains: cur } = await chrome.storage.local.get("neverSaveDomains");
      await chrome.storage.local.set({
        neverSaveDomains: (cur || []).filter((d) => d !== domain),
      });
      await renderNeverList();
    });
    li.append(span, rm);
    ul.appendChild(li);
  }
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
