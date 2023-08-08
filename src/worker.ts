import { Context, Hono } from 'hono'
import { Cookie, MemoryCookieStore } from 'tough-cookie'
import { Fetcher } from './carelink'

export type Env = {
  COOKIES: KVNamespace
  MINIMED_USER: string
  MINIMED_PASSWORD: string
  PASSWORD: string
}

const app = new Hono<{ Bindings: Env }>()

app.post(
  '/fetch',
  authWrapper(async (credentials, c) => {
    const passwordHash = await sha1(
      `${credentials.username}@${credentials.password}`,
    )
    const { cookieStore, saveCookies } = await setupCookie(
      c.env.COOKIES,
      passwordHash,
    )

    const fetcher = new Fetcher(cookieStore, {
      CARELINK_USERNAME: credentials.username,
      CARELINK_PASSWORD: credentials.password,
      COUNTRY: credentials.country,
      LANG: credentials.language,
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

async function sha1(text: string) {
  const ab = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text))
  return Array.from(new Uint8Array(ab))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
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

function authWrapper(
  f: (
    credentials: Credentials,
    c: Context<{ Bindings: Env }>,
  ) => Promise<Response>,
): (c: Context<{ Bindings: Env }>) => Promise<Response> {
  return async (c) => {
    const legacyPassword = c.req
      .header('Authorization')
      ?.match(/^Bearer\s+(.+?)\s*$/)?.[1]
    if (legacyPassword !== undefined) {
      if (legacyPassword === c.env.PASSWORD) {
        return f(
          {
            username: c.env.MINIMED_USER,
            password: c.env.MINIMED_PASSWORD,
            language: 'ja',
            country: 'jp',
          },
          c,
        )
      } else {
        return c.text('Unauthorized', 401)
      }
    }

    let credentials: Credentials

    try {
      credentials = await c.req.json<Credentials>()
      if (
        !credentials.username ||
        !credentials.password ||
        !credentials.country ||
        !credentials.language
      ) {
        return c.text('Unauthorized', 401)
      }
    } catch (e) {
      return c.text('Unauthorized', 401)
    }

    return f(credentials, c)
  }
}
