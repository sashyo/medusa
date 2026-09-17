/**
 * minidauth field sealing for Medusa (MikroORM repository layer).
 *
 * Seals selected personal fields - a customer's name, phone and company, and the name, phone, company
 * and street lines on an address - with minidauth before they reach Postgres, and opens them again on
 * the way out. The crypto runs in the minidauth-seal sidecar, which talks to minidauth and the Tide
 * ORK cohort: this app, and Postgres, only ever hold ciphertext. The vendor key lives as threshold
 * shares across the ORK network and is never assembled here, so a stolen database or a leaked backup
 * is unreadable, and a quorum - not this app - decides whether records can be read at all (the reader
 * must hold a quorum-granted role, or `open` returns nothing and the field stays sealed).
 *
 * Off by default. Set MINIDAUTH_SEAL_URL to point at the sidecar to turn it on; unset, every path
 * below is a no-op and Medusa behaves exactly like upstream.
 *
 * Wired into MikroOrmBaseRepository: create/update seal inbound data before persist, serialize opens
 * the returned records (batched). Model keys are matched on the MikroORM entity name, lowercased.
 *
 * Proof of concept. The remaining limit is queryability - a sealed column holds ciphertext, so the
 * database cannot sort, filter or search on it, which is why lookup and routing keys stay in the clear
 * (see SEALED): a customer's email (login key), and an address's city / postal_code / province /
 * country (tax, shipping and region logic branch on them).
 */
import { currentReaderToken } from "./minidauth-reader"

const sealUrl = (): string | undefined => process.env.MINIDAUTH_SEAL_URL
export const minidauthEnabled = (): boolean => Boolean(sealUrl())

// lowercased MikroORM entity name -> the scalar string fields to seal.
const SEALED: Record<string, string[]> = {
  customer: ["company_name", "first_name", "last_name", "phone"],
  customeraddress: ["company", "first_name", "last_name", "phone", "address_1", "address_2"],
  orderaddress: ["company", "first_name", "last_name", "phone", "address_1", "address_2"],
}

const MARKER = "ms1:"
const isSealed = (v: unknown): v is string => typeof v === "string" && v.startsWith(MARKER)
const sealedFieldsFor = (entityName: string | undefined): string[] =>
  entityName ? SEALED[entityName.toLowerCase()] ?? [] : []

async function sidecar(path: string, body: unknown, bearer?: string): Promise<any> {
  const headers: Record<string, string> = { "Content-Type": "application/json" }
  if (bearer) {
    headers["Authorization"] = `Bearer ${bearer}`
  }
  const r = await fetch(sealUrl() + path, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  })
  const text = await r.text()
  if (!r.ok) {
    throw new Error(`minidauth-seal ${path} -> ${r.status} ${text}`)
  }
  return text ? JSON.parse(text) : {}
}

// A leaf is one string value we can read and write in place, so the same code seals and opens it.
type Leaf = { get: () => unknown; set: (v: unknown) => void }
const leaf = (obj: any, key: string): Leaf => ({
  get: () => obj[key],
  set: (v) => (obj[key] = v),
})

/** Collect the plaintext leaves to seal on a create/update payload for one entity. */
function collectWriteLeaves(entityName: string | undefined, data: any, out: Leaf[]): void {
  if (!data || typeof data !== "object") {
    return
  }
  for (const f of sealedFieldsFor(entityName)) {
    const v = data[f]
    if (typeof v === "string" && v.length > 0) {
      out.push(leaf(data, f))
    }
  }
}

/** Collect the sealed leaves to open on a serialized record (or array of records) for one entity. */
function collectReadLeaves(entityName: string | undefined, node: any, out: Leaf[]): void {
  if (!node || typeof node !== "object") {
    return
  }
  if (Array.isArray(node)) {
    node.forEach((n) => collectReadLeaves(entityName, n, out))
    return
  }
  for (const f of sealedFieldsFor(entityName)) {
    if (isSealed(node[f])) {
      out.push(leaf(node, f))
    }
  }
}

// Seal fails closed: if the sidecar is unreachable, the write throws rather than storing plaintext.
async function sealLeaves(leaves: Leaf[]): Promise<void> {
  if (leaves.length === 0) {
    return
  }
  const fields: Record<string, string> = {}
  leaves.forEach((l, i) => (fields[String(i)] = l.get() as string))
  // The sidecar returns marker-included values (it decides what is genuine ciphertext), so store them
  // as-is; prepending the marker here would double it.
  const { sealed } = await sidecar("/seal", { fields })
  leaves.forEach((l, i) => l.set((sealed as Record<string, string>)[String(i)]))
}

let openWarned = false
// Open is best-effort and gated on the reader's verified identity: decryption runs as the end user
// named in a token this request carries (withMinidauthReader), and only if minidauth's quorum grant
// says that user holds the reading role. No reader in context, an ungranted reader, or a sidecar that
// is down all leave the field sealed rather than crashing the read - ciphertext is the safe failure.
async function openLeaves(leaves: Leaf[]): Promise<void> {
  if (leaves.length === 0) {
    return
  }
  const readerToken = currentReaderToken()
  if (!readerToken) {
    if (!openWarned) {
      openWarned = true
      // eslint-disable-next-line no-console
      console.warn("[minidauth-seal] no reader identity in context; leaving records sealed")
    }
    return
  }
  try {
    const fields: Record<string, string> = {}
    leaves.forEach((l, i) => (fields[String(i)] = (l.get() as string).slice(MARKER.length)))
    const { fields: opened } = await sidecar("/open", { fields }, readerToken)
    leaves.forEach((l, i) => l.set((opened as Record<string, string>)[String(i)]))
  } catch (e) {
    if (!openWarned) {
      openWarned = true
      // eslint-disable-next-line no-console
      console.warn("[minidauth-seal] leaving records sealed:", (e as Error).message)
    }
  }
}

/** Seal the SEALED string fields on each create/update payload (batched into one cohort fan-out). */
export async function sealForWrite(entityName: string | undefined, data: any[]): Promise<void> {
  if (!minidauthEnabled() || sealedFieldsFor(entityName).length === 0) {
    return
  }
  const leaves: Leaf[] = []
  for (const d of data) {
    // update() payloads look like { entity, update }; create() payloads are the record itself.
    collectWriteLeaves(entityName, d && typeof d === "object" && "update" in d ? d.update : d, leaves)
  }
  await sealLeaves(leaves)
}

/** Open the SEALED string fields on a serialized record or array (batched into one cohort fan-out). */
export async function openForRead(entityName: string | undefined, output: any): Promise<void> {
  if (!minidauthEnabled() || !output || sealedFieldsFor(entityName).length === 0) {
    return
  }
  const leaves: Leaf[] = []
  collectReadLeaves(entityName, output, leaves)
  await openLeaves(leaves)
}
