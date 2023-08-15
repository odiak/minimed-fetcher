import { Context, Hono } from 'hono'
import { Cookie, MemoryCookieStore } from 'tough-cookie'
import { Fetcher } from './carelink'

export type Env = {
  COOKIES: KVNamespace
  SALT: string
}

const app = new Hono<{ Bindings: Env }>()

app.post(
  '/fetch',
  authWrapper(async ({ username, password, language, country, hash }, c) => {
    const { cookieStore, saveCookies } = await setupCookie(c.env.COOKIES, hash)

    const fetcher = new Fetcher(cookieStore, {
      CARELINK_USERNAME: username,
      CARELINK_PASSWORD: password,
      COUNTRY: country,
      LANG: language,
    })
    const res = await fetcher.fetchData()

    await saveCookies()

    if (res === undefined) {
      return c.json({ error: 'Failed to fetch data' }, 500)
    }

    return res
  }),
)

export default app

async function calcHash(
  salt: string,
  username: string,
  password: string,
): Promise<string> {
  const text = `${salt}${username}@${password}`
  const ab = await crypto.subtle.digest(
    'SHA-512',
    new TextEncoder().encode(text),
  )
  return btoa(String.fromCharCode(...new Uint8Array(ab)))
}

async function setupCookie(kv: KVNamespace, key: string) {
  const cookieStore = new MemoryCookieStore()
  const rawCookies = await kv.get(key, 'json')
  if (Array.isArray(rawCookies)) {
    for (const rawCookie of rawCookies) {
      const cookie = Cookie.fromJSON(rawCookie)
      if (cookie) {
        cookieStore.putCookie(cookie)
      }
    }
  }

  async function saveCookies() {
    const cookies = await cookieStore.getAllCookies()
    await kv.put(key, JSON.stringify(cookies.map((c) => c.toJSON())))
  }

  return { cookieStore, saveCookies }
}

type Credentials = {
  username: string
  password: string
  language: string
  country: string
}

type CredentialsWithHash = Credentials & {
  hash: string
}

function authWrapper(
  f: (
    credentials: CredentialsWithHash,
    c: Context<{ Bindings: Env }>,
  ) => Promise<Response>,
): (c: Context<{ Bindings: Env }>) => Promise<Response> {
  return async (c) => {
    let credentials: Credentials
    try {
      credentials = await c.req.json<Credentials>()
      assertNonEmptyString(credentials.username)
      assertNonEmptyString(credentials.password)
      assertNonEmptyString(credentials.language)
      assertNonEmptyString(credentials.country)
    } catch (e) {
      return c.text('Unauthorized', 401)
    }

    const hash = await calcHash(
      c.env.SALT,
      credentials.username,
      credentials.password,
    )

    return f({ ...credentials, hash }, c)
  }
}

function assertNonEmptyString(s: unknown): asserts s is string {
  if (typeof s !== 'string' || s.length === 0) {
    throw new Error('Invalid string')
  }
}
