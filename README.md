# SvelteKit OpenID Connect

This is an attempt to port [express-openid-connect](https://github.com/auth0/express-openid-connect) for use with SvelteKit

[![NPM version](https://img.shields.io/npm/v/sveltekit-openid-connect.svg?style=flat-square)](https://npmjs.org/package/sveltekit-openid-connect)

### Open issues for questions or concerns

## Table of Contents

- [Documentation](#documentation)
- [Install](#install)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [Support + Feedback](#support--feedback)
- [Vulnerability Reporting](#vulnerability-reporting)
- [What is Auth0](#what-is-auth0)
- [License](#license)

## Install (Pending)

Node.js version **>=16.0.0** is recommended

```bash
npm install sveltekit-openid-connect
```

## Getting Started

### Initializing

> svelte.config.js
```js
const config = {
	kit: {
		csrf: { // This is required due to a breaking change in sveltekit see https://github.com/starbasehq/sveltekit-openid-connect/issues/11
			checkOrigin: false
		}
	}
}
```

> src/hooks.server.js

```js
import * as cookie from 'cookie'
import { TokenUtils } from 'sveltekit-openid-connect'
import { SessionService } from '$lib/services' // This is a service that provides session storage, not a part of this package
import fetch from 'node-fetch'

const {
    AUTH0_DOMAIN,
    AUTH0_BASE_URL,
    AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET,
    COOKIE_SECRET,
    AUTH0_AUDIENCE,
	CSRF_ALLOWED
} = process.env

const csrfAllowed = [`https://${AUTH0_DOMAIN}`, ...(CSRF_ALLOWED || '').split(',').filter(Boolean)]

const sessionName = 'sessionName'
const auth0config = {
    attemptSilentLogin: true,
    authRequired: false,
    auth0Logout: true, // Boolean value to enable Auth0's logout feature.
    baseURL: AUTH0_BASE_URL,
    clientID: AUTH0_CLIENT_ID,
    issuerBaseURL: `https://${AUTH0_DOMAIN}`,
    secret: COOKIE_SECRET,
    clientSecret: AUTH0_CLIENT_SECRET,
    authorizationParams: {
        scope: 'openid profile offline_access email',
        response_type: 'code id_token',
        audience: AUTH0_AUDIENCE
    },
    session: {
        name: 'sessionName', // Replace with custom session name
        cookie: {
            path: '/'
        },
        absoluteDuration: 86400,
        rolling: false,
        rollingDuration: false
    }
}

// This was added to support decrypting the encrypted session cookies we utilized
const tokenUtils = new TokenUtils(auth0config)

export async function handle ({ event, resolve }) {
	const { forbidden: forbidCSRF, response: responseCSRF } = checkCSRF(event.request)
	if (forbidCSRF) return responseCSRF
    try {
        const request = event.request
        event.locals.isAuthenticated = false
        const cookies = cookie.parse(request.headers.get('cookie') || '')
        const { url, body, params } = request
        const path = url.pathname
        const query = url.searchParams
        let sessionCookie

		let sessionValid = false
		let session = {}
		if (cookies.session_id) event.locals.sessionId = cookies.session_id
        try {
			if (event.cookies.get('session_id') && event.cookies.get(sessionName)) {
				const cookieToken = event.cookies.get(sessionName)
				session = await sessionService.get(cookies.session_id, cookieToken)
				try {
					if (tokenUtils.isExpired(cookieToken)) {
						console.warn('Token is expired, try to renew')
						// TODO: Needs Testing
						// TODO: Support refresh tokens?
						return Response.redirect(`/auth/login?returnTo=${event.url.pathname}`, 401)
					} else {
						const idToken = tokenUtils.getIdToken({ token: cookieToken })
						const sToken = session.data
						if (sToken.exp < idToken.exp) {
							console.debug('Cookie is Newer, update session')
							// Update session from your session service
							await session.save()
						}
						if (sToken.sub === idToken.sub && sToken.iss === idToken.iss) {
							console.info('Cookie and Session match')
							sessionValid = true
						} else {
							console.error('Cookie and Session failed to match, do something')
						}
						console.info('Token is valid, not expired')
					}
				} catch (tErr) {
					console.trace(tErr)
				}

				event.locals.sessionId = cookies.session_id

				if (session) {
                    // assign session information to event.locals here
                    /*
                        event.locals.user = session.data.user
                    */
                }
            } else {
                console.warn('No session found, better send to auth')
				// perform sveltekit redirect
            }
        } catch (err) {
            console.error('problem getting app session', err.message)
            // perform sveltekit redirect
        }

        const response = await resolve(request) // This is required by sveltekit

        // Optional: add the session cookie
        if (sessionCookie) {
            const existingCookies = (response.headers && response.headers.get('set-cookie')) ? response.headers.get('set-cookie') : []
            response.headers.set('set-cookie', [...existingCookies, sessionCookie])
        }

        return response
    } catch (err) {
        console.error('Problem running handle', err.message)
    }
}

export async function getSession (event) {
    // This has been deprecated in sveltekit, it is safe to delete, it is moved to +layout.server.js
}

// This is required due to sveltekit changes see https://github.com/starbasehq/sveltekit-openid-connect/issues/11
function checkCSRF (request) {
	const url = new URL(request.url)
	const type = request.headers.get('content-type')?.split(';')[0]
	const forbidden =
		request.method === 'POST' &&
		!_.includes([url.origin, ...csrfAllowed], request.headers.get('origin')) &&
		(type === 'application/x-www-form-urlencoded' || type === 'multipart/form-data')

	if (forbidden) {
		console.warn('Prevent CSRF')
		const response = new Response(`Cross-site ${request.method} form submissions are forbidden`, {
			status: 403
		})
		return { forbidden, response }
	} else {
		return { forbidden, response: null }
	}
}
```

> src/routes/+layout.server.js

```js
export async function load ({ locals }) {
	return {
		session: {
			isAuthenticated: locals.isAuthenticated,
			sessionId: locals.sessionId,
			user: locals.user
		}
	}
}
```

### Logging in

The endpoint route can be different but must be changed in the config block for routes
> src/routes/auth/login/+server.js

```js
import { Auth } from 'sveltekit-openid-connect'

const {
    AUTH0_DOMAIN,
    AUTH0_BASE_URL,
    AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET,
    COOKIE_SECRET,
    AUTH0_AUDIENCE
} = process.env

const auth0config = {
    attemptSilentLogin: true,
    authRequired: false,
    auth0Logout: true, // Boolean value to enable Auth0's logout feature.
    baseURL: AUTH0_BASE_URL,
    clientID: AUTH0_CLIENT_ID,
    issuerBaseURL: `https://${AUTH0_DOMAIN}`,
    secret: COOKIE_SECRET,
    clientSecret: AUTH0_CLIENT_SECRET,
    authorizationParams: {
        scope: 'openid profile offline_access email groups permissions roles',
        response_type: 'code id_token',
        audience: AUTH0_AUDIENCE
    },
    routes: {
        login: '/auth/login',
        logout: '/auth/logout',
        callback: '/auth/callback'
    }
}

const auth0 = new Auth(auth0config)

export async function get ({ request }, ...otherProps) {
    const loginResponse = await auth0.handleLogin()

	return new Response(JSON.stringify({}), {
		status: 302,
		headers: {
			location: loginResponse.authorizationUrl,
			'Set-Cookie': loginResponse.cookies
		}
	})
}
```

### Handling the callback

The endpoint route can be different but must be changed in the config block for routes
> src/routes/auth/callback/+server.js

```js
import _ from 'lodash'
import * as cookie from 'cookie'
import { Auth, appSession } from 'sveltekit-openid-connect'
import mock from 'mock-http'
import { SessionService } from '$lib/services'

const sessionService = new SessionService()

const {
    AUTH0_DOMAIN,
    AUTH0_BASE_URL,
    AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET,
    COOKIE_SECRET,
    AUTH0_AUDIENCE
} = process.env

const auth0config = {
    attemptSilentLogin: true,
    authRequired: false,
    auth0Logout: true, // Boolean value to enable Auth0's logout feature.
    baseURL: AUTH0_BASE_URL,
    clientID: AUTH0_CLIENT_ID,
    issuerBaseURL: `https://${AUTH0_DOMAIN}`,
    secret: COOKIE_SECRET,
    clientSecret: AUTH0_CLIENT_SECRET,
    authorizationParams: {
        scope: 'openid profile offline_access email',
        response_type: 'code id_token',
        audience: AUTH0_AUDIENCE
    },
    session: {
        name: 'sessionName',
        cookie: {
            path: '/'
        },
        absoluteDuration: 86400,
        rolling: false,
        rollingDuration: false
    }
}

const auth0 = new Auth(auth0config)

export async function post ({ request }) {
    const { headers } = request
    const body = await request.formData()
    const cookies = cookie.parse(headers.get('cookie') || '')
    if (_.isObject(cookies)) {
        const req = new mock.Request({
            url: request.url,
            method: 'POST',
            headers,
            buffer: Buffer.from(JSON.stringify({
                code: body.get('code'),
                state: body.get('state'),
                id_token: body.get('id_token')
            }))
        })
        req.cookies = cookies
        req.body = {
            code: body.get('code'),
            state: body.get('state'),
            id_token: body.get('id_token')
        }

        const res = new mock.Response()

        const authResponse = await auth0.handleCallback(req, res, cookies)
        const session = await appSession(auth0config)(req, res, authResponse.session)

		// Optional to allow restoring an existing session
		const rReturn = new URL(authResponse.redirect.returnTo)
		let sessionId = cookies['session_id'] || rReturn.searchParams.get('sid')
		let sessionRestored = false
		let sessionCookie

		if (sessionId) {
			const restoredSession = await sessionService.restoreSession(sessionId, authResponse.session)
			if (restoredSession.ok) {
				sessionRestored = true
			}
		}

		if (!sessionRestored) {
			const newSession = await sessionService.createSession(authResponse.session)
			sessionId = newSession.sessionId
			sessionCookie = cookie.serialize('session_id', sessionId, {
				httpOnly: true,
				maxAge: 60 * 60 * 24 * 30,
				sameSite: 'lax',
				path: '/'
			})
		}

        return new Response(JSON.stringify({
			error: false
		}), {
			status: 302,
			headers: {
				location: '/',
				'set-cookie': _.concat(authResponse.cookies, session.cookies, sessionCookie).filter(Boolean)
			}
		})
    } else {
		return new Response(JSON.stringify({
			error: true
		}))
	}
}

```

### Destroying the Session

> src/routes/auth/logout/+server.js

```js
import * as cookie from 'cookie'
import { Auth } from 'sveltekit-openid-connect'
import mock from 'mock-http'

const {
    AUTH0_DOMAIN,
    AUTH0_BASE_URL,
    AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET,
    COOKIE_SECRET,
    AUTH0_AUDIENCE
} = process.env

const auth0config = {
    attemptSilentLogin: true,
    authRequired: false, // Require authentication for all routes.
    auth0Logout: true, // Boolean value to enable Auth0's logout feature.
    baseURL: AUTH0_BASE_URL,
    clientID: AUTH0_CLIENT_ID,
    issuerBaseURL: `https://${AUTH0_DOMAIN}`,
    secret: COOKIE_SECRET,
    clientSecret: AUTH0_CLIENT_SECRET,
    authorizationParams: {
        scope: 'openid profile offline_access email groups permissions roles',
        response_type: 'code id_token',
        audience: AUTH0_AUDIENCE
    },
    session: {
        name: 'sessionName',
        cookie: {
            path: '/'
        },
        absoluteDuration: 86400,
        rolling: false,
        rollingDuration: false
    },
    routes: {
        login: '/auth/login',
        logout: '/auth/logout',
        callback: '/auth/callback'
    }
}

const auth0 = new Auth(auth0config)

export async function get ({ locals, request }) {
    const { headers } = request
    const cookies = cookie.parse(headers.get('cookie') || '')

    const res = new mock.Response()
    const logoutResponse = await auth0.handleLogout(request, res, cookies, Object.assign(locals))

	// Optional, remove this if you want to support restoring previous session
    const sessionCookie = cookie.serialize('session_id', 'deleted', {
        httpOnly: true,
        expires: new Date(),
        sameSite: 'lax',
        path: '/'
    })

    return new Response(JSON.stringify({}), {
		status: 302,
		headers: {
			location: logoutResponse.returnURL,
			'Set-Cookie': [...logoutResponse.cookies]
		}
	})
}
```

### Sample Session Service

> src/lib/services/session.js

```js
import jwtDecode from 'jwt-decode'
import { v4 as uuidv4 } from 'uuid'
import DB from './db' // Custom database service using sequelize
import UserService from './user'

const db = new DB()
const userService = new UserService()

class SessionService {
    async createSession (authSession) {
        const sqldb = await db.getDatabase()
        const sessionId = uuidv4()
        const session = await jwtDecode(authSession.id_token)
        console.log('Create Session', session)

        // enrich with raw oidc session data
        session.oidc = authSession

        const { email, sub } = session
        const [identitySource, userIdentifier] = sub.split('|')
        const userData = {
            identitySource,
            userIdentifier,
            email,
            user_id: sub
        }

        const userProfile = await userService.get(userData)

        const { UserId, ...other } = userProfile

        session.UserId = UserId
        session.user = {}
        session.user.other = other

        const [sessionStore, created] = await sqldb.SessionStore.findOrCreate({
            where: {
                sessionId
            },
            defaults: {
                data: session,
                sessionId,
                UserId
            }
        })

        if (created) {
            console.log('Created SessionStore', sessionStore._id)
        }

        return { sessionId, session: sessionStore }
    }

    async get (sessionId) {
        const session = await getSession(sessionId)

        return session
    }

    async decodeJwt (jwt) {
        return jwtDecode(jwt)
    }

	async restoreSession (sessionId, authSession) {
		const rSession = await getSession(sessionId)

		if (!rSession) return { ok: false }

		const session = await jwtDecode(authSession.id_token)

		// enrich with raw oidc session data
		session.oidc = authSession

		const { email, sub } = session
		const [identitySource, userIdentifier] = sub.split('|')
		const userData = {
			identitySource,
			userIdentifier,
			email,
			user_id: sub
		}

		if (session.sub !== rSession.data.sub) {
			console.info(`Session is not for authed User ${session.sub} vs ${rSession.data.sub}`)
			return { ok: false }
		}

		const userProfile = await userService.get(userData)

		const { orgs, projects } = userProfile
		session.user = {}
		session.user.orgs = orgs || []
		session.user.projects = projects || []

		try {
			rSession.data = Object.assign(rSession.data, session)
			rSession.changed('data', true)

			await rSession.save()
			return { ok: true }
		} catch (e) {
			console.error(e.message)
			return { ok: false }
		}
	}
}

async function getSession (sessionId) {
    const sqldb = await db.getDatabase()
    const session = await sqldb.SessionStore.findOne({
        where: {
            sessionId
        }
    })

    return session
}

export default SessionService
```

> src/lib/services/db.js

```js
import _ from 'lodash'
import orm from '<<sequelize orm project>>'

const config = {
    sequelize: {
        // eslint-disable-next-line dot-notation
        sync: process.env['DB_SYNC'],
        // eslint-disable-next-line dot-notation
        syncForce: process.env['DB_SYNC_FORCE'],
        // eslint-disable-next-line dot-notation
        database: process.env['DB_DATABASE'] ,
        // eslint-disable-next-line dot-notation
        host: process.env['DB_HOST'] || '127.0.0.1',
        // eslint-disable-next-line dot-notation
        port: process.env['DB_PORT'],
        // eslint-disable-next-line dot-notation
        username: process.env['DB_USERNAME'],
        // eslint-disable-next-line dot-notation
        password: process.env['DB_PASSWORD'],
        // eslint-disable-next-line dot-notation
        dbDefault: process.env['DB_DEFAULT'] || 'postgres',
        dialectOptions: {
            // eslint-disable-next-line dot-notation
            ssl: process.env['DB_SSL'] === 'true'
        }
    }
}

const sqldb = orm(config)
class DatabaseService {
    async getDatabase () {
        return sqldb
    }
}
export default DatabaseService
```

> src/lib/services/user.js

```js
import _ from 'lodash'
import DB from './db'

const db = new DB()

class UserService {
    async get (userData) {
        const sqldb = await db.getDatabase()

        const [user, created] = await sqldb.User.findOrCreate({
            where: {
                email: userData.email
            },
            defaults: userData
        })

        if (!created) {
            if (!user.userIdentifier) {
                await updateUserAttributes(user, userData)
            }
            console.debug('Existing User')
            return {
                UserId: user._id
            }
        } else {
            console.debug('created new user', JSON.stringify(user, null, 2))
            return {
                UserId: user._id
            }
        }
    }
}

async function updateUserAttributes (user, aUser) {
    const identitySource = (aUser.identitySource) ? aUser.identitySource : aUser.identities[0].provider // TODO: should we always assume 0?
    const userIdentifier = (aUser.userIdentifier) ? aUser.userIdentifier : aUser.identities[0].user_id // TODO: should we always assume 0?

    user.identitySource = identitySource
    user.userIdentifier = userIdentifier
    user.user_id = aUser.user_id
    await user.save()
}

export default UserService
```


## Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

Contributions can be made to this library through PRs to fix issues, improve documentation or add features. Please fork this repo, create a well-named branch, and submit a PR with a complete template filled out.

Code changes in PRs should be accompanied by tests covering the changed or added functionality. Tests can be run for this library with:

```bash
npm install
npm test
```

When you're ready to push your changes, please run the lint command first:

```bash
npm run lint
```

## Support + Feedback

Please use the [Issues queue](https://github.com/starbasehq/sveltekit-openid-connect/issues) in this repo for questions and feedback.

## What is Auth0?

Auth0 helps you to easily:

- implement authentication with multiple identity providers, including social (e.g., Google, Facebook, Microsoft, LinkedIn, GitHub, Twitter, etc), or enterprise (e.g., Windows Azure AD, Google Apps, Active Directory, ADFS, SAML, etc.)
- log in users with username/password databases, passwordless, or multi-factor authentication
- link multiple user accounts together
- generate signed JSON Web Tokens to authorize your API calls and flow the user identity securely
- access demographics and analytics detailing how, when, and where users are logging in
- enrich user profiles from other data sources using customizable JavaScript rules

[Why Auth0?](https://auth0.com/why-auth0)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
