/**
 * Per-user reader identity for minidauth field opening (Medusa).
 *
 * The sidecar holds NO reading identity of its own: it decrypts only on behalf of an end user named
 * in a token it verifies, and only if minidauth's quorum grant says that user holds the reading role.
 * The read path has to carry WHO is reading down to the repository layer, which gets no request
 * context of its own, so we thread it ourselves: an API middleware wraps the request in
 * `withMinidauthReader(userId, fn)`, and the seal layer reads the current reader from this store when
 * it opens sealed fields. No reader in context means the field stays sealed - ciphertext is the safe
 * default, never an open decryption oracle.
 */
import { AsyncLocalStorage } from "async_hooks"
import { createHmac, createPrivateKey, sign as edSign, type KeyObject } from "crypto"
import { readFileSync } from "fs"

const readerStore = new AsyncLocalStorage<{ userToken: string }>()

const b64url = (b: Buffer | string): string =>
  (Buffer.isBuffer(b) ? b : Buffer.from(b, "utf8"))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")

// Prefer an Ed25519 private key only this app holds (MINIDAUTH_SEAL_SIGNING_KEY_FILE): minidauth
// verifies it with the public half, so there is no shared secret to leak. The HS256 secret is a
// quick-start fallback.
let cachedKey: KeyObject | null | undefined
const signingKey = (): KeyObject | null => {
  if (cachedKey === undefined) {
    const file = process.env.MINIDAUTH_SEAL_SIGNING_KEY_FILE
    const pem = file ? readFileSync(file, "utf8") : process.env.MINIDAUTH_SEAL_SIGNING_KEY
    cachedKey = pem ? createPrivateKey(pem) : null
  }
  return cachedKey
}
const readerSecret = (): string | undefined => process.env.MINIDAUTH_SEAL_TOKEN_SECRET

/**
 * Mint a short-lived assertion that this already-authenticated user is the reader. Medusa has already
 * verified the user (the id comes from the request auth context, never from the client body); this
 * token just carries that verified identity to the sidecar, which re-verifies the signature and
 * decrypts as this uid. minidauth's quorum grant decides whether the uid may actually read.
 */
export function mintReaderToken(uid: string): string {
  const now = Math.floor(Date.now() / 1000)
  const payload = b64url(JSON.stringify({ sub: uid, iat: now, exp: now + 15 }))
  const key = signingKey()
  if (key) {
    const header = b64url(JSON.stringify({ alg: "EdDSA", typ: "JWT" }))
    const sig = b64url(edSign(null, Buffer.from(`${header}.${payload}`), key))
    return `${header}.${payload}.${sig}`
  }
  const secret = readerSecret()
  if (!secret) {
    throw new Error(
      "Set MINIDAUTH_SEAL_SIGNING_KEY_FILE (preferred) or MINIDAUTH_SEAL_TOKEN_SECRET"
    )
  }
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))
  const sig = b64url(createHmac("sha256", secret).update(`${header}.${payload}`).digest())
  return `${header}.${payload}.${sig}`
}

/** Run `fn` with `uid` as the minidauth reader, so any sealed field read inside it opens as that user. */
export function withMinidauthReader<T>(
  uid: string | number | null | undefined,
  fn: () => T
): T {
  if (uid === null || uid === undefined || uid === "") {
    return fn()
  }
  return readerStore.run({ userToken: mintReaderToken(String(uid)) }, fn)
}

/** The current reader's token, or undefined outside a withMinidauthReader scope (reads stay sealed). */
export function currentReaderToken(): string | undefined {
  return readerStore.getStore()?.userToken
}
