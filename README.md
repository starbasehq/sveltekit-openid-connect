# SvelteKit OpenID Connect

This is an attempt to port [express-openid-connect](https://github.com/auth0/express-openid-connect) for use with SvelteKit

[![NPM version](https://img.shields.io/npm/v/sveltekit-openid-connect.svg?style=flat-square)](https://npmjs.org/package/sveltekit-openid-connect)

## ⚠️⚠️ WARNING: This is not fully tested, there are unnecessary console.logs as well as some unimplemented code. Open issues for questions or concerns ⚠️⚠️

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

Node.js version **>=12.0.0** is recommended, but **^10.19.0** lts/dubnium is also supported.

```bash
npm install sveltekit-openid-connect
```

## Getting Started

### Initializing

> src/hooks.js || src/hooks/index.js

```js
import * as cookie from 'cookie'
import mock from 'mock-http'
import { appSession } from 'sveltekit-openid-connect'
import { SessionService } from '$lib/services' // This is a service that provides session storage, not a part of this package
import fetch from 'node-fetch'

const {
    AUTH0_DOMAIN,
    AUTH0_BASE_URL,
    AUTH0_CLIENT_ID,
    AUTH0_CLIENT_SECRET,
    COOKIE_SECRET,
    AUTH0_AUDIENCE
} = process.env

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

export async function handle ({ event, resolve }) {
    try {
        const request = event.request
        event.locals.isAuthenticated = false
        const cookies = cookie.parse(request.headers.get('cookie') || '')
        const { url, body, params } = request
        const path = url.pathname
        const query = url.searchParams
        let sessionCookie
        const req = new mock.Request({
            url: path,
            headers: request.headers
        })
        req.cookies = cookies

        try {
            if (cookies.session_id) { // Use if you are storing a session_id in a cookie to look up cookie in DB or other store
                event.locals.sessionId = cookies.session_id
                const session = await sessionService.get(cookies.session_id)
                if (session) {
                    // assign session information to event.locals here
                    /*
                        event.locals.user = session.data.user
                    */
                }
            } else if (cookies[sessionName]) {
                const contextSession = await appSession(auth0config)(req)

                // Start section for creating session inside a session store
                const { session, sessionId } = await sessionService.createSession(contextSession.oidc)
                sessionCookie = cookie.serialize('session_id', sessionId, {
                    httpOnly: true,
                    maxAge: 60 * 60 * 24 * 1,
                    sameSite: 'lax',
                    path: '/'
                })
                // End session store

                // assign session information to event.locals here from either contextSession or session
                /*
                    event.locals.user = session.data.user
                    event.locals.oidc = session.data.oidc
                    event.locals.isAuthenticated = true
                */
            } else {
                console.warn('No session found, better send to auth')
                event.locals.redirect = '/auth/login'
            }
        } catch (err) {
            console.error('problem getting app session', err.message)
            event.locals.redirect = '/auth/login'
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
    const session = {
        isAuthenticated: !!event.locals.user,
        user: event.locals.user && event.locals.user
    }

    if (event.locals.user) {
        session.user.property = event.locals.user.property
        /*
         * This is an example of something can can be done but not what we actually use
         *
         */
        /*
            // TODO: We need to enrich the user
            const userUrl = `${API_HOST}/api/users/me`
            const userProfile = await fetch(userUrl, {
                headers: {
                    Authorization: `Bearer ${event.locals.oidc.access_token}`
                }
            })
                .then(res => res.json())
        */
    }

    return session
}
```

### Logging in

The endpoint route can be different but must be changed in the config block for routes
> src/routes/auth/login.js

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

    return {
        headers: {
            location: loginResponse.authorizationUrl,
            'Set-Cookie': loginResponse.cookies
        },
        status: 302,
        body: {}
    }
}
```

### Handling the callback

The endpoint route can be different but must be changed in the config block for routes
> src/routes/auth/callback.js

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

        const { sessionId } = await sessionService.createSession(authResponse.session)
        const sessionCookie = cookie.serialize('session_id', sessionId, {
            httpOnly: true,
            maxAge: 60 * 60 * 24 * 1,
            sameSite: 'lax',
            path: '/'
        })

        return {
            headers: {
                location: '/',
                'set-cookie': _.concat(authResponse.cookies, session.cookies)
            },
            status: 302,
            body: {
                error: false
            }
        }
    } else {
        return {
            body: {
                error: true
            }
        }
    }
}

```

### Destroying the Session

> src/routes/auth/logout.js

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

    const sessionCookie = cookie.serialize('session_id', 'deleted', {
        httpOnly: true,
        expires: new Date(),
        sameSite: 'lax',
        path: '/'
    })

    return {
        headers: {
            location: logoutResponse.returnURL,
            'Set-Cookie': [...logoutResponse.cookies, sessionCookie]
        },
        status: 302,
        body: {}
    }
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
        // TODO: we should be caching this somehow, right?
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
                // TODO: should we check identity source?
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
