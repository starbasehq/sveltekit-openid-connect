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

export async function handle ({ request, resolve }) {
    try {
        request.locals.isAuthenticated = false
        const cookies = cookie.parse(request.headers.cookie || '')
        const { path, body, query, params } = request
        let sessionCookie
        const req = new mock.Request({
            url: path,
            headers
        })
        req.cookies = cookies

        try {
            if (cookies.session_id) { // Use if you are storing a session_id in a cookie to look up cookie in DB or other store
                request.locals.sessionId = cookies.session_id
                const session = await sessionService.get(cookies.session_id)
                if (session) {
                    // assign session information to request.locals here
                    /*
                        request.locals.user = session.data.user
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

                // assign session information to request.locals here from either contextSession or session
                /*
                    request.locals.user = session.data.user
                */
            } else {
                console.warn('No session found, better send to auth')
                request.locals.redirect = '/auth/login'
            }
        } catch (err) {
            console.error('problem getting app session', err.message)
            request.locals.redirect = '/auth/login'
        }

        const response = await resolve(request) // This is required by sveltekit

        // Optional: add the session cookie
        if (sessionCookie) {
            const existingCookies = (response.headers && response.headers['set-cookie']) ? response.headers['set-cookie'] : []
            response.headers['set-cookie'] = [...existingCookies, sessionCookie]
        }

        return {
            ...response,
            headers: {
                ...response.headers
            }
        }
    } catch (err) {
        console.error('Problem running handle', err.message)
    }
}

export async function getSession (request) {
    const session = {
        isAuthenticated: !!request.locals.user,
        user: request.locals.user && request.locals.user
    }

    if (request.locals.user) {
        // TODO: We need to enrich the user
        const userUrl = `${API_HOST}/api/users/me`
        const userProfile = await fetch(userUrl, {
            headers: {
                Authorization: `Bearer ${request.locals.oidc.access_token}`
            }
        })
            .then(res => res.json())
    }

    return session
}
```

### Logging in

The endpoint route can be different but must be changed in the config block for routes
> src/routes/auth/login.js

```js
import { Auth } from 'sveltekit-openid-connect'

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

export async function get (request, ...otherProps) {
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

export async function post (request) {
    const { headers, body } = request
    const cookies = cookie.parse(headers.cookie || '')
    if (_.isObject(cookies)) {
        const req = new mock.Request({
            url: request.path,
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

### Destroying the Session (NOT IMPLEMENTED YET)

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

export async function get (request) {
    const { headers } = request
    const cookies = cookie.parse(headers.cookie || '')
    const req = new mock.Request({
        url: request.path,
        headers
    })
    req.cookies = cookies

    const res = new mock.Response()
    const logoutResponse = await auth0.handleLogout(req, res, cookies, request.locals)

    return {
        headers: {
            location: logoutResponse.returnURL,
            'Set-Cookie': logoutResponse.cookies
        },
        status: 302,
        body: {}
    }
}
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
