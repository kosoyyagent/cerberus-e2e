// Cerberus end to end: five chambers driven in fixed order, no network.
// Order: identity -> trust score -> intent -> SOUL handshake -> session token.
// Each chamber returns {ok:true,...} or {ok:false,reason}. First refusal wins.
// Chambers are injected so this suite can drive the Kognai-provided
// interfaces as-is, or the reference implementations below.
import { createHmac, randomBytes, createHash } from 'node:crypto';

// ---------- reference chambers (fixture driven, no network) ----------

// chamber 1 identity: caller supplied verifySig(signer,msg,sig)->bool.
export function identityChamber({ verifySig }) {
  return ({ challenge, signature, owner }) => {
    if (!challenge?.did || !challenge?.listingId || !challenge?.expiresAt)
      return { ok: false, reason: 'malformed_challenge' };
    if (Date.parse(challenge.expiresAt) <= Date.now())
      return { ok: false, reason: 'expired_challenge' };
    const msg = `cerberus.identity:${challenge.did}:${challenge.listingId}:${challenge.nonce}`;
    return verifySig(owner, msg, signature)
      ? { ok: true, did: challenge.did }
      : { ok: false, reason: 'bad_signature' };
  };
}

// chamber 2 trust: policy {minTier} over a scoreAgent-like record.
export function trustChamber({ minTier = 'bronze' }) {
  const order = ['unproven', 'bronze', 'silver', 'gold'];
  return ({ score, tier }) =>
    order.indexOf(tier) >= order.indexOf(minTier)
      ? { ok: true, score, tier }
      : { ok: false, reason: `tier ${tier} below ${minTier}` };
}

// chamber 3 intent: declared intent must be allowed and within budget.
export function intentChamber({ allowed, maxUsdc }) {
  return ({ intent, priceUsdc }) => {
    if (!allowed.includes(intent)) return { ok: false, reason: 'intent_not_allowed' };
    if (Number(priceUsdc) > maxUsdc) return { ok: false, reason: 'over_budget' };
    return { ok: true };
  };
}

// chamber 4 SOUL handshake: sha256 of soul document must match its checksum line.
export function soulChamber() {
  return ({ soulMd, declaredSha256 }) => {
    const actual = createHash('sha256').update(String(soulMd), 'utf8').digest('hex');
    return actual === String(declaredSha256).toLowerCase()
      ? { ok: true, soulSha256: actual }
      : { ok: false, reason: 'soul_checksum_mismatch' };
  };
}

// chamber 5 session token: HMAC token with expiry.
export function sessionChamber({ secret, ttlMs = 3_600_000 }) {
  const sign = p => createHmac('sha256', secret).update(p).digest('hex');
  return {
    issue: ({ did, tier, now = Date.now() }) => {
      const exp = now + ttlMs;
      const payload = `${did}|${tier}|${exp}`;
      return { token: `${payload}|${sign(payload)}`, expiresAt: exp };
    },
    verify: ({ token, now = Date.now() }) => {
      const parts = String(token || '').split('|');
      if (parts.length !== 4) return { ok: false, reason: 'malformed_token' };
      const payload = parts.slice(0, 3).join('|');
      if (sign(payload) !== parts[3]) return { ok: false, reason: 'tampered_token' };
      if (Number(parts[2]) <= now) return { ok: false, reason: 'token_expired' };
      return { ok: true, did: parts[0], tier: parts[1] };
    },
  };
}

// ---------- pipeline ----------

// ctx: {challenge,signature,owner,score,tier,intent,priceUsdc,soulMd,declaredSha256,now}
export function runCerberus({ chambers, ctx }) {
  const steps = ['identity', 'trust', 'intent', 'soul', 'session'];
  const trail = {};
  for (const name of steps) {
    const ch = chambers[name];
    const r = name === 'session' ? ch.issue(ctx) : ch(ctx);
    trail[name] = r;
    if (r.ok === false) return { ok: false, refusedAt: name, reason: r.reason, trail };
    if (name === 'session') return { ok: true, session: r, trail };
  }
  return { ok: true, trail };
}
