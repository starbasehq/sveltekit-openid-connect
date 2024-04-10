/* eslint-disable camelcase */
import url from 'url'
import urlJoin from 'url-join'
import { JWT } from 'jose'
import { TokenSet } from 'openid-client'
import clone from 'clone'
import { strict as assert } from 'assert'
import createError from 'http-errors'

// const debug = req_uire('./debug')('context')
// import { once } from './once.js'
import getClient from './client'
import { encodeState, decodeState } from '../src/hooks/getLoginState'
import onLogin from './hooks/backchannelLogout/onLogIn'
import onLogoutToken from './hooks/backchannelLogout/onLogoutToken'
// import {
// 	cancelSilentLogin,
// 	resumeSilentLogin,
// } from '../middleware/attemptSilentLogin'
import weakRef from './weakCache'
import {
	regenerateSessionStoreId,
	replaceSession,
} from '../src/appSession'

function isExpired () {
	return tokenSet.call(this).expired()
}

async function refresh({ tokenEndpointParams } = {}) {
	const { config, req } = weakRef(this)
	const { client } = await getClient(config)
	const oldTokenSet = tokenSet.call(this)

	let extras;
	if (config.tokenEndpointParams || tokenEndpointParams) {
		extras = {
			exchangeBody: { ...config.tokenEndpointParams, ...tokenEndpointParams },
		};
	}

	const newTokenSet = await client.refresh(oldTokenSet, extras)

	// Update the session
	const session = req[config.session.name]
	Object.assign(session, {
		id_token: newTokenSet.id_token,
		access_token: newTokenSet.access_token,
		// If no new refresh token assume the current refresh token is valid.
		refresh_token: newTokenSet.refresh_token || oldTokenSet.refresh_token,
		token_type: newTokenSet.token_type,
		expires_at: newTokenSet.expires_at
	})

	// Delete the old token set
	const cachedTokenSet = weakRef(session)
	delete cachedTokenSet.value

	return this.accessToken
}

function tokenSet () {
	const contextCache = weakRef(this)
	const session = contextCache.req[contextCache.config.session.name]

	if (!session || !('id_token' in session)) {
		return undefined
	}

	const cachedTokenSet = weakRef(session)

	if (!('value' in cachedTokenSet)) {
		const {
			id_token,
			access_token,
			refresh_token,
			token_type,
			expires_at
		} = session
		cachedTokenSet.value = new TokenSet({
			id_token,
			access_token,
			refresh_token,
			token_type,
			expires_at
		})
	}

	return cachedTokenSet.value
}

class RequestContext {
	constructor (config, req, res, next) {
		Object.assign(weakRef(this), { config, req, res, next })
	}

	isAuthenticated () {
		return !!this.idTokenClaims
	}

	get idToken () {
		try {
			return tokenSet.call(this).id_token
		} catch (err) {
			return undefined
		}
	}

	get refreshToken () {
		try {
			return tokenSet.call(this).refresh_token
		} catch (err) {
			return undefined
		}
	}

	get accessToken () {
		try {
			const { access_token, token_type, expires_in } = tokenSet.call(this)

			if (!access_token || !token_type || typeof expires_in !== 'number') {
				return undefined
			}

			return {
				access_token,
				token_type,
				expires_in,
				isExpired: isExpired.bind(this),
				refresh: refresh.bind(this)
			}
		} catch (err) {
			return undefined
		}
	}

	get idTokenClaims () {
		try {
			const {
				config: { session },
				req,
			} = weakRef(this);

			// The ID Token from Auth0's Refresh Grant doesn't contain a "sid"
			// so we should check the backup sid we stored at login.
			const { sid } = req[session.name];
			return { sid, ...clone(tokenSet.call(this).claims()) };
		} catch (err) {
			return undefined;
		}
	}

	get user () {
		try {
			const {
				config: { identityClaimFilter }
			} = weakRef(this)
			const { idTokenClaims } = this
			const user = clone(idTokenClaims)
			identityClaimFilter.forEach((claim) => {
				delete user[claim]
			})
			return user
		} catch (err) {
			return undefined
		}
	}

	async fetchUserInfo () {
		const { config } = weakRef(this)

		const { client } = await getClient(config)
		return client.userinfo(tokenSet.call(this))
	}
}

class ResponseContext {
	constructor (config, req, res, next, transient) {
		Object.assign(weakRef(this), { config, req, res, next, transient })
	}

	get errorOnRequiredAuth () {
		return weakRef(this).config.errorOnRequiredAuth
	}

	getRedirectUri () {
		const { config } = weakRef(this)
		if (config.routes.callback) {
			return urlJoin(config.baseURL, config.routes.callback);
		}
	}

	silentLogin (options) {
		return this.login({
			...options,
			silent: true,
			authorizationParams: { ...options.authorizationParams, prompt: 'none' },
		})
	}

	async login (options = {}) {
		const { config, req, res, transient } = weakRef(this)

		try {
			const { client } = await getClient(config)
			// Set default returnTo value, allow passed-in options to override or use originalUrl on GET
			let returnTo = config.baseURL
			if (options.returnTo) {
				returnTo = options.returnTo
				console.debug('req.oidc.login() called with returnTo: %s', returnTo)
			} else if (req.method === 'GET' && req.originalUrl) {
				// Collapse any leading slashes to a single slash to prevent Open Redirects
				returnTo = req.originalUrl.replace(/^\/+/, '/')
				console.debug('req.oidc.login() without returnTo, using: %s', returnTo)
			}

			options = {
				authorizationParams: {},
				returnTo,
				...options,
			}

			// Ensure a redirect_uri, merge in configuration options, then passed-in options.
			options.authorizationParams = {
				redirect_uri: this.getRedirectUri(),
				...config.authorizationParams,
				...options.authorizationParams,
			}

			const stateValue = await config.getLoginState(req, options)
			if (typeof stateValue !== 'object') {
				console.error(new Error('Custom state value must be an object.'))
			}


			if (options.silent) {
				stateValue.attemptingSilentLogin = true;
			}

			const validResponseTypes = ['id_token', 'code id_token', 'code']
			assert(
				validResponseTypes.includes(options.authorizationParams.response_type),
				`response_type should be one of ${validResponseTypes.join(', ')}`
			)
			assert(
				/\bopenid\b/.test(options.authorizationParams.scope),
				'scope should contain "openid"'
			)


			const authVerification = {
				nonce: transient.generateNonce(),
				state: encodeState(stateValue),
				...(options.authorizationParams.max_age
				? {
					max_age: options.authorizationParams.max_age,
					}
				: undefined),
			}

			let authParams = {
				...options.authorizationParams,
				...authVerification,
			}

			const usePKCE = options.authorizationParams.response_type.includes('code')
			if (usePKCE) {
				console.debug(
					'response_type includes code, the authorization request will use PKCE 2024'
				)
				// stateValue.code_verifier = transient.generateCodeVerifier()
				authVerification.code_verifier = transient.generateCodeVerifier();

				authParams.code_challenge_method = 'S256';
				authParams.code_challenge = transient.calculateCodeChallenge(
					authVerification.code_verifier
				)
			}


			if (config.pushedAuthorizationRequests) {
				const { request_uri } = await client.pushedAuthorizationRequest(
					authParams
				)
				authParams = { request_uri };
			}

			transient.store(config.transactionCookie.name, req, res, {
				sameSite: options.authorizationParams.response_mode === 'form_post' ? 'None' : config.transactionCookie.sameSite,
				value: JSON.stringify(authVerification)
			})

			const authorizationUrl = client.authorizationUrl(authParams)
			console.debug('redirecting to %s', authorizationUrl)
			// res.redirect(authorizationUrl)
			return {
				authorizationUrl,
				cookies: transient.getCookies()
			}
		} catch (err) {
			console.trace('error from ResponseContext.login')
			throw err
		}
	}

	async logout (params = {}, res) {
		console.debug('logout params', params)
		let { config, req, transient } = weakRef(this)

		let returnURL = params.returnTo || config.routes.postLogoutRedirect
		console.debug('req.oidc.logout() with return url: %s', returnURL)

		try {
			const { client } = await getClient(config);
			if (url.parse(returnURL).host === null) {
				returnURL = urlJoin(config.baseURL, returnURL)
			}

			// cancelSilentLogin(req, res)

			// if (!req.oidc.isAuthenticated()) {
			if (!params.isAuthenticated) {
				console.debug('end-user already logged out, redirecting to %s', returnURL)
				// 	return res.redirect(returnURL)
				return {
					returnURL
				}
			}

			const { id_token: id_token_hint } = params.oidc
			// req[config.session.name] = undefined

			if (!config.idpLogout) {
				console.debug('performing a local only logout, redirecting to %s', returnURL)
				// return res.redirect(returnURL)
				return {
					returnURL
				}
			}

			returnURL = client.endSessionUrl({
				...config.logoutParams,
				id_token_hint,
				post_logout_redirect_uri: returnURL,
				...params.logoutParams,
			})
		} catch (err) {
			console.error(err)
		}

		console.debug('logging out of identity provider, redirecting to %s', returnURL)
		transient.store(config.session.name, req, res, {
			sameSite: config.session.cookie.sameSite,
			value: 'deleted',
		})
		transient.deleteCookie(config.session.name, res)
		// res.redirect(returnURL)
		return {
			returnURL,
			cookies: transient.getCookies()
		}
	}

	async callback(options = {}) {
		let { config, req, res, transient, next } = weakRef(this)
		// next = once(next);
		try {
			const { client } = await getClient(config)
			const redirectUri = options.redirectUri || this.getRedirectUri()

			let tokenSet
			try {
			const callbackParams = client.callbackParams(req)
			const authVerification = transient.getOnce(
				config.transactionCookie.name,
				req,
				res
			)

			const checks = authVerification ? JSON.parse(authVerification) : {}

			req.openidState = decodeState(checks.state)

			tokenSet = await client.callback(redirectUri, callbackParams, checks, {
				exchangeBody: {
				...(config && config.tokenEndpointParams),
				...options.tokenEndpointParams,
				}
			})
			} catch (error) {
				throw createError(400, error.message, {
					error: error.error,
					error_description: error.error_description,
				})
			}

			let session = Object.assign({}, tokenSet) // Remove non-enumerable methods from the TokenSet
			const claims = tokenSet.claims()
			// Must store the `sid` separately as the ID Token gets overridden by
			// ID Token from the Refresh Grant which may not contain a sid (In Auth0 currently).
			session.sid = claims.sid

			if (config.afterCallback) {
				session = await config.afterCallback(
					req,
					res,
					session,
					req.openidState
				)
			}

			if (req.oidc.isAuthenticated()) {
				if (req.oidc.user.sub === claims.sub) {
					// If it's the same user logging in again, just update the existing session.
					Object.assign(req[config.session.name], session)
				} else {
					// If it's a different user, replace the session to remove any custom user
					// properties on the session
					replaceSession(req, session, config)
					// And regenerate the session id so the previous user wont know the new user's session id
					await regenerateSessionStoreId(req, config)
				}
			} else {
				// If a new user is replacing an anonymous session, update the existing session to keep
				// any anonymous session state (eg. checkout basket)
				Object.assign(req[config.session.name], session)
				// But update the session store id so a previous anonymous user wont know the new user's session id
				await regenerateSessionStoreId(req, config)
			}
			// resumeSilentLogin(req, res)

			if (
				req.oidc.isAuthenticated() &&
				config.backchannelLogout &&
				config.backchannelLogout.onLogin !== false
			) {
				await (config.backchannelLogout.onLogin || onLogin)(req, config)
			}
		} catch (err) {
			if (!req.openidState || !req.openidState.attemptingSilentLogin) {
				// return next(err);
				console.trace(err)
			}
		}
		res.redirect(req.openidState.returnTo || config.baseURL)
	}

	async backchannelLogout() {
		let { config, req, res } = weakRef(this)
		res.setHeader('cache-control', 'no-store')
		const logoutToken = req.body.logout_token
		if (!logoutToken) {
			res.status(400).json({
				error: 'invalid_request',
				error_description: 'Missing logout_token'
			})
			return
		}
		const onToken =
			(config.backchannelLogout && config.backchannelLogout.onLogoutToken) ||
			onLogoutToken
		let token
		try {
			const { issuer } = await getClient(config)
			const keyInput = await issuer.keystore()

			token = await JWT.LogoutToken.verify(logoutToken, keyInput, {
				issuer: issuer.issuer,
				audience: config.clientID,
				algorithms: [config.idTokenSigningAlg]
			})
		} catch (e) {
			res.status(400).json({
				error: 'invalid_request',
				error_description: e.message,
			})
			return
		}
		try {
			await onToken(token, config)
		} catch (e) {
			console.debug('req.oidc.backchannelLogout() failed with: ', e.message)
			res.status(400).json({
				error: 'application_error',
				error_description: `The application failed to invalidate the session.`
			})
			return
		}
		res.status(204).send()
	}
}

export { RequestContext, ResponseContext }
