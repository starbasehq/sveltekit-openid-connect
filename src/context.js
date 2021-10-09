/* eslint-disable camelcase */
// const cb = req_uire('cb')
import url from 'url'
import urlJoin from 'url-join'
import { TokenSet } from 'openid-client'
import clone from 'clone'
import { strict as assert } from 'assert'

// const debug = req_uire('./debug')('context')
import getClient from './client'
import { encodeState } from './hooks/getLoginState'
// const { cancelSilentLogin } = req_uire('../middleware/attemptSilentLogin')
import weakRef from './weakCache'

function isExpired () {
	return tokenSet.call(this).expired()
}

async function refresh () {
	const { config, req } = weakRef(this)
	const client = await getClient(config)
	const oldTokenSet = tokenSet.call(this)
	const newTokenSet = await client.refresh(oldTokenSet)

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
			return clone(tokenSet.call(this).claims())
		} catch (err) {
			return undefined
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

		const client = await getClient(config)
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
		return urlJoin(config.baseURL, config.routes.callback)
	}

	silentLogin (options) {
		return this.login({
			...options,
			prompt: 'none'
		})
	}

	async login (options = {}) {
		const { config, req, res, transient } = weakRef(this)
		// next = cb(next).once()
		const client = await getClient(config)

		// Set default returnTo value, allow passed-in options to override or use originalUrl on GET
		let returnTo = config.baseURL
		if (options.returnTo) {
			returnTo = options.returnTo
			console.log('req.oidc.login() called with returnTo: %s', returnTo)
		} else if (req.method === 'GET' && req.originalUrl) {
			returnTo = req.originalUrl
			console.log('req.oidc.login() without returnTo, using: %s', returnTo)
		}

		options = {
			authorizationParams: {},
			returnTo,
			...options
		}

		// Ensure a redirect_uri, merge in configuration options, then passed-in options.
		options.authorizationParams = {
			redirect_uri: this.getRedirectUri(),
			...config.authorizationParams,
			...options.authorizationParams
		}

		const stateValue = await config.getLoginState(req, options)
		if (typeof stateValue !== 'object') {
			throw new Error('Custom state value must be an object.')
		}
		stateValue.nonce = transient.generateNonce()

		const usePKCE = options.authorizationParams.response_type.includes('code')
		if (usePKCE) {
			console.log(
				'response_type includes code, the authorization request will use PKCE'
			)
			stateValue.code_verifier = transient.generateCodeVerifier()
		}

		try {
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
						max_age: options.authorizationParams.max_age
					}
					: undefined)
			}
			const authParams = {
				...options.authorizationParams,
				...authVerification
			}

			if (usePKCE) {
				authVerification.code_verifier = transient.generateNonce()

				authParams.code_challenge_method = 'S256'
				authParams.code_challenge = transient.calculateCodeChallenge(
					authVerification.code_verifier
				)
			}

			transient.store('auth_verification', req, res, {
				sameSite: options.authorizationParams.response_mode === 'form_post' ? 'None' : config.session.cookie.sameSite,
				value: JSON.stringify(authVerification)
			})

			const authorizationUrl = client.authorizationUrl(authParams)
			console.log('redirecting to %s', authorizationUrl)
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
		console.log('logout params', params)
		let { config, req, transient } = weakRef(this)
		// next = cb(next).once()
		const client = await getClient(config)

		let returnURL = params.returnTo || config.routes.postLogoutRedirect
		console.log('req.oidc.logout() with return url: %s', returnURL)

		if (url.parse(returnURL).host === null) {
			returnURL = urlJoin(config.baseURL, returnURL)
		}

		// cancelSilentLogin(req, res)

		// if (!req.oidc.isAuthenticated()) {
		if (!params.isAuthenticated) {
			console.log('end-user already logged out, redirecting to %s', returnURL)
			// 	return res.redirect(returnURL)
			return {
				returnURL
			}
		}

		const { id_token: id_token_hint } = params.oidc
		// req[config.session.name] = undefined

		if (!config.idpLogout) {
			console.log('performing a local only logout, redirecting to %s', returnURL)
			// return res.redirect(returnURL)
			return {
				returnURL
			}
		}

		returnURL = client.endSessionUrl({
			post_logout_redirect_uri: returnURL,
			id_token_hint
		})

		console.log('logging out of identity provider, redirecting to %s', returnURL)
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
}

export { RequestContext, ResponseContext }
