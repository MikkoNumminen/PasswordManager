// Offscreen document: clears a copied secret from the clipboard 30s after a
// copy, but only if the clipboard still holds that value (so it never clobbers
// something the user copied since). Best-effort: if the clipboard APIs are
// unavailable here, it quietly does nothing.

chrome.runtime.onMessage.addListener(async (msg) => {
  if (msg.target !== "offscreen" || msg.type !== "clipboard-clear") return;
  try {
    const current = await navigator.clipboard.readText();
    if (current === msg.value) {
      await navigator.clipboard.writeText("");
    }
  } catch {
    // no clipboard access here; leave it alone
  } finally {
    window.close();
  }
});
