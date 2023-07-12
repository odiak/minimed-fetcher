import fetchCookie from 'fetch-cookie'
import { CookieJar, MemoryCookieStore } from 'tough-cookie'

type Env = {
  CARELINK_USERNAME: string
  CARELINK_PASSWORD: string
  COUNTRY: string
  LANG: string
}

const CARELINK_TOKEN_COOKIE = 'auth_tmp_token'
const CARELINK_TOKEN_EXPIRE_COOKIE = 'c_token_valid_to'

const CARELINK_BASE_URL = 'https://carelink.minimed.eu'
const CARELINK_REFRESH_TOKEN_URL = `${CARELINK_BASE_URL}/patient/sso/reauth`
const CARELINK_LOGIN_URL = `${CARELINK_BASE_URL}/patient/sso/login`

export class Fetcher {
  private _fetch: typeof fetch
  private token: string | undefined

  constructor(
    private cookieStore: MemoryCookieStore,
    private env: Env,
  ) {
    this._fetch = fetchCookie(fetch, new CookieJar(cookieStore))
  }

  private fetch(...[request, init]: Parameters<typeof fetch>) {
    const headers = new Headers({
      Accept: '*/*',
      'User-Agent': 'test',
      ...init?.headers,
    })

    if (this.token !== undefined) {
      headers.set('Authorization', `Bearer ${this.token}`)
    }

    return this._fetch(request, {
      redirect: 'manual',
      ...init,
      headers,
    })
  }

  async fetchData() {
    try {
      await this.checkLogin()
      return await this.getConnectData()
    } catch (e) {
      console.log('error: ', e)
      await this.deleteCookies()
      return undefined
    }
  }

  private async checkLogin(reLogin = false) {
    if (
      !reLogin &&
      ((await this.hasCookie(CARELINK_TOKEN_COOKIE)) ||
        (await this.hasCookie(CARELINK_TOKEN_EXPIRE_COOKIE)))
    ) {
      const token = await this.getCookie(CARELINK_TOKEN_COOKIE)
      if (token !== undefined) {
        this.token = token
      }

      const expire = await this.getCookie(CARELINK_TOKEN_EXPIRE_COOKIE)

      // Refresh token if expires in 6 minutes
      if (
        expire !== undefined &&
        Date.parse(expire) - 6 * 60 * 1000 < Date.now()
      ) {
        await this.refreshToken()
      }
    } else {
      await this.doLogin()
    }
  }

  private async hasCookie(cookieName: string): Promise<boolean> {
    return (await this.cookieStore.getAllCookies()).some(
      (cookie) => cookie.key === cookieName,
    )
  }
  private async getCookie(cookieName: string): Promise<string | undefined> {
    return (await this.cookieStore.getAllCookies()).find(
      (cookie) => cookie.key === cookieName,
    )?.value
  }
  private deleteCookies() {
    return this.cookieStore.removeAllCookies()
  }

  private async refreshToken() {
    try {
      await this.fetch(CARELINK_REFRESH_TOKEN_URL, {
        method: 'POST',
      })
      this.token = await this.getCookie(CARELINK_TOKEN_COOKIE)
    } catch (e) {
      console.log(`error at refreshToken(): ${e}`)
      await this.deleteCookies()
      await this.checkLogin(true)
    }
  }

  private async doLogin() {
    const step1 = async () => {
      const url = new URL(CARELINK_LOGIN_URL)
      url.searchParams.set('country', this.env.COUNTRY)
      url.searchParams.set('lang', this.env.LANG)
      return await this.fetch(url)
    }
    const step2 = async (prevRes: Response) => {
      let res = prevRes
      while (true) {
        const next = res.headers.get('location')
        if (next === null) return res
        res = await this.fetch(next)
      }
    }
    const step3 = async (res: Response) => {
      const { action, sessionId, sessionData } = await parseForm(res)

      const newRes = await this.fetch(action, {
        method: 'POST',
        body: new URLSearchParams({
          sessionID: sessionId,
          sessionData: sessionData,
          locale: this.env.LANG,
          action: 'login',
          username: this.env.CARELINK_USERNAME,
          password: this.env.CARELINK_PASSWORD,
          actionButton: 'Log in',
        }),
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        },
      })

      if ((await newRes.clone().text()).includes(action.pathname)) {
        throw new Error('Invalid username or password')
      }

      return newRes
    }
    const step4 = async (res: Response) => {
      const { action, sessionId, sessionData } = await parseForm(res)

      return await this.fetch(action, {
        method: 'POST',
        body: new URLSearchParams({
          action: 'consent',
          sessionID: sessionId,
          sessionData: sessionData,
          response_type: 'code',
          response_mode: 'query',
        }),
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        },
      })
    }
    const step5 = async (res: Response) => {
      const next = ensure(
        res.headers.get('location'),
        'Missing location header',
      )
      const newRes = await this.fetch(next)
      this.cookieStore.removeCookie('carelink.minimed.eu', '/', 'codeVerifier')
      this.token = ensure(await this.getCookie(CARELINK_TOKEN_COOKIE))
      return newRes
    }

    const res1 = await step1()
    const res2 = await step2(res1)
    const res3 = await step3(res2)
    const res4 = await step4(res3)
    await step5(res4)
  }

  private async getConnectData() {
    const roleRes = await this.fetch(`${CARELINK_BASE_URL}/patient/users/me`)
    const { role } = await roleRes.json<{ role: string }>()

    const settingsUrl = new URL(
      `${CARELINK_BASE_URL}/patient/countries/settings`,
    )
    settingsUrl.searchParams.set('countryCode', this.env.COUNTRY)
    settingsUrl.searchParams.set('language', this.env.LANG)
    const settingsRes = await this.fetch(settingsUrl)

    type Settings = {
      blePereodicDataEndpoint: string
    }

    const { blePereodicDataEndpoint: dataUrl } =
      await settingsRes.json<Settings>()

    return await this.fetch(dataUrl, {
      method: 'POST',
      body: JSON.stringify({
        patientId: this.env.CARELINK_USERNAME,
        username: this.env.CARELINK_USERNAME,
        role: role.startsWith('PATIENT') ? 'patient' : 'carepartner',
      }),
      headers: { 'Content-Type': 'application/json' },
    })
  }
}

function ensure<T extends {}>(
  value: T | undefined | null,
  message?: string,
): T {
  if (value === undefined || value === null) {
    throw new Error(message ?? `unexpected: ${value}`)
  }
  return value
}

async function parseForm(res: Response) {
  const body = await res.text()
  const action = new URL(
    ensure(
      body.match(/<form\s+.*?action="([^"]+)"\s+method="POST"/m)?.[1],
      'Missing action',
    ),
  )
  const sessionId = ensure(
    body.match(/<input\s+.*?name="sessionID"\s+value="([^"]+)"/m)?.[1],
    'Missing sessionID',
  )
  const sessionData = ensure(
    body.match(/<input\s+.*?name="sessionData"\s+value="([^"]+)"/m)?.[1],
    'Missing sessionData',
  )
  return { action, sessionId, sessionData }
}
