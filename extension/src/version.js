// Version comparison for the update notice. Pure and node-tested. Compares
// dotted numeric versions ("0.2.0"); anything it cannot parse yields false so
// a malformed value never nags the user to update.

function parts(v) {
  if (typeof v !== "string" || !v.trim()) return null;
  const segs = v.trim().split(".");
  const nums = [];
  for (const s of segs) {
    if (!/^\d+$/.test(s)) return null; // reject empty, signs, "v0", etc.
    nums.push(Number(s));
  }
  return nums;
}

// True when `latest` is strictly greater than `current`.
export function isBehind(current, latest) {
  const c = parts(current);
  const l = parts(latest);
  if (!c || !l) return false;
  const len = Math.max(c.length, l.length);
  for (let i = 0; i < len; i++) {
    const a = c[i] || 0;
    const b = l[i] || 0;
    if (b > a) return true;
    if (b < a) return false;
  }
  return false;
}
