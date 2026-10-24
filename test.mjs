import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { identityChamber, trustChamber, intentChamber, soulChamber, sessionChamber, runCerberus }
  from './index.mjs';

const fx = JSON.parse(readFileSync(new URL('./fixtures/cases.json', import.meta.url)));
const G = fx.good, P = fx.policy;
const sha = s => createHash('sha256').update(s, 'utf8').digest('hex');
const soulSha = sha(G.soulMd);

// toy signature verifier over fixtures: good sig = 'sig-' + signer suffix
const verifySig = (signer, msg, sig) => sig === `sig-${signer === '0xOwner' ? 'good' : 'bad'}`;

const chambers = {
  identity: identityChamber({ verifySig }),
  trust: trustChamber({ minTier: P.minTier }),
  intent: intentChamber({ allowed: P.allowed, maxUsdc: P.maxUsdc }),
  soul: soulChamber(),
  session: sessionChamber({ secret: P.sessionSecret }),
};
const ctx = o => ({ ...G, declaredSha256: soulSha, ...o });

// ---- full pipeline ----
test('e2e: all five chambers pass -> session issued', () => {
  const r = runCerberus({ chambers, ctx: ctx() });
  assert.equal(r.ok, true);
  assert.ok(r.session.token.split('|').length === 4);
});

// ---- chamber 1 identity ----
test('identity: malformed challenge refused', () => {
  const r = runCerberus({ chambers, ctx: ctx({ challenge: {} }) });
  assert.equal(r.refusedAt, 'identity'); assert.equal(r.reason, 'malformed_challenge');
});
test('identity: expired challenge refused', () => {
  const r = runCerberus({ chambers, ctx: ctx({ challenge: { ...G.challenge, expiresAt: '2000-01-01T00:00:00Z' } }) });
  assert.equal(r.refusedAt, 'identity'); assert.equal(r.reason, 'expired_challenge');
});
test('identity: wrong signer refused', () => {
  const r = runCerberus({ chambers, ctx: ctx({ owner: '0xMallory' }) });
  assert.equal(r.refusedAt, 'identity'); assert.equal(r.reason, 'bad_signature');
});
test('identity: forged signature refused', () => {
  const r = runCerberus({ chambers, ctx: ctx({ signature: 'sig-fake' }) });
  assert.equal(r.refusedAt, 'identity');
});
test('identity: passes on its own', () =>
  assert.equal(chambers.identity(ctx()).ok, true));

// ---- chamber 2 trust ----
test('trust: unproven refused', () => {
  const r = runCerberus({ chambers, ctx: ctx({ tier: 'unproven', score: 0 }) });
  assert.equal(r.refusedAt, 'trust');
});
test('trust: bronze at minTier passes', () =>
  assert.equal(chambers.trust({ tier: 'bronze', score: 40 }).ok, true));
test('trust: gold passes', () =>
  assert.equal(chambers.trust({ tier: 'gold', score: 90 }).ok, true));
test('trust: strict gold policy refuses silver', () => {
  const t = trustChamber({ minTier: 'gold' });
  assert.equal(t({ tier: 'silver', score: 70 }).ok, false);
});

// ---- chamber 3 intent ----
test('intent: disallowed intent refused', () => {
  const r = runCerberus({ chambers, ctx: ctx({ intent: 'spam' }) });
  assert.equal(r.refusedAt, 'intent'); assert.equal(r.reason, 'intent_not_allowed');
});
test('intent: over budget refused', () => {
  const r = runCerberus({ chambers, ctx: ctx({ priceUsdc: 101 }) });
  assert.equal(r.refusedAt, 'intent'); assert.equal(r.reason, 'over_budget');
});
test('intent: at cap passes', () =>
  assert.equal(chambers.intent({ intent: 'hire', priceUsdc: 100 }).ok, true));

// ---- chamber 4 SOUL handshake ----
test('soul: checksum mismatch refused', () => {
  const r = runCerberus({ chambers, ctx: ctx({ declaredSha256: '0'.repeat(64) }) });
  assert.equal(r.refusedAt, 'soul'); assert.equal(r.reason, 'soul_checksum_mismatch');
});
test('soul: tampered document refused', () => {
  const r = runCerberus({ chambers, ctx: ctx({ soulMd: G.soulMd + 'lie' }) });
  assert.equal(r.refusedAt, 'soul');
});
test('soul: correct checksum passes', () =>
  assert.equal(chambers.soul({ soulMd: G.soulMd, declaredSha256: soulSha }).ok, true));

// ---- chamber 5 session token ----
test('session: token verifies within ttl', () => {
  const s = sessionChamber({ secret: 'k' });
  const t = s.issue({ did: 'd', tier: 'silver', now: 1000 });
  assert.equal(s.verify({ token: t.token, now: 2000 }).ok, true);
});
test('session: expired token refused', () => {
  const s = sessionChamber({ secret: 'k', ttlMs: 10 });
  const t = s.issue({ did: 'd', tier: 's', now: 1000 });
  assert.equal(s.verify({ token: t.token, now: 1011 }).reason, 'token_expired');
});
test('session: tampered did refused', () => {
  const s = sessionChamber({ secret: 'k' });
  const t = s.issue({ did: 'd', tier: 's', now: 1 });
  const bad = t.token.replace('d|', 'mallory|');
  assert.equal(s.verify({ token: bad, now: 2 }).reason, 'tampered_token');
});
test('session: tampered expiry refused', () => {
  const s = sessionChamber({ secret: 'k' });
  const t = s.issue({ did: 'd', tier: 's', now: 1 });
  const parts = t.token.split('|'); parts[2] = '9999999999999';
  assert.equal(s.verify({ token: parts.join('|'), now: 2 }).reason, 'tampered_token');
});
test('session: malformed token refused', () =>
  assert.equal(sessionChamber({ secret: 'k' }).verify({ token: 'x', now: 1 }).reason, 'malformed_token'));

// ---- ordering ----
test('order: trust refusal precedes intent', () => {
  const r = runCerberus({ chambers, ctx: ctx({ tier: 'unproven', intent: 'spam' }) });
  assert.equal(r.refusedAt, 'trust');
});
test('order: soul refusal precedes session', () => {
  const r = runCerberus({ chambers, ctx: ctx({ declaredSha256: 'bad' }) });
  assert.equal(r.refusedAt, 'soul');
});
