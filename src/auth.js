// const cb = req_uire('cb')
import createError from 'http-errors'

// const debug = req_uire('../lib/debug')('auth')
import getConfig from './config'
import getClient from './client'
import TransientCookieHandler from './transientHandler'
import { ResponseContext } from './context'
import _ from 'lodash'
import { decodeState } from './hooks/getLoginState'
import AppSession from './appSession'

/**
 * Returns a router with two routes /login and /callback
 *
 * @param {Object} [params] The parameters object; see index.d.ts for types and descriptions.
 *
 * @returns auth tool
 */
export default class Auth {
	constructor (params) {
		this.config = getConfig(params)
		this.transient = new TransientCookieHandler(this.config)
	}

	static async client () {
		const client = this.client || (await getClient(this.config).catch((err) => { throw err }))

		if (!client) {
			return
		}
		return this.client
	}

	async handleCallback (req, res, /* cookies */) {
		const client = this.client || (await getClient(this.config).catch((err) => { throw err }))
		let next
		req.oidc = new ResponseContext(this.config, req, res, next, this.transient)
		let openidState

		if (!client) {
			return
		}
		try {
			// TODO: Build Full URL?
			const redirectUri = req.oidc.getRedirectUri()

			let session

			try {
				const callbackParams = client.callbackParams(req)
				// console.log('callbackParams', callbackParams, redirectUri)
				const authVerification = this.transient.getOnce(
					'auth_verification',
					req,
					res
					// Request
					// Response
				)
				// console.log('authVerification', authVerification)

				// eslint-disable-next-line camelcase
				const { max_age, code_verifier, nonce, state } = authVerification
					? JSON.parse(authVerification)
					: {}

				session = await client.callback(redirectUri, callbackParams, {
					max_age,
					code_verifier,
					nonce,
					state
				})
				openidState = decodeState(state)
			} catch (err) {
				console.log(err)
				throw createError.BadRequest(err.message)
			}

			// if (this.config.afterCallback) {
			// 	session = await this.config.afterCallback(
			// 		req,
			// 		res,
			// 		Object.assign({}, session), // Remove non-enumerable methods from the TokenSet
			// 		req.openidState
			// 	)
			// }

			return {
				session,
				redirect: openidState || this.config.baseURL,
				cookies: res.cookies
			}

			// Object.assign(req[config.session.name], session)
			// attemptSilentLogin.resumeSilentLogin(req, res)
		} catch (err) {
			console.log('auth.js handleCallback', err)
			return {
				session: undefined,
				redirect: this.config.baseURL
			}
		}
	}

	async handleLogin (returnToQuery = '', returnUrl) {
		let req, res, next
		const oidc = new ResponseContext(this.config, req, res, next, this.transient)
		const returnTo = (returnUrl || this.config.baseURL) + returnToQuery
		const loginResponse = await oidc.login({ returnTo })
		const { authorizationUrl } = loginResponse
		const cookies = prepareCookies(loginResponse.cookies)

		return {
			authorizationUrl,
			cookies
		}
	}

	async handleLogout (req, res, reqCookies, context) {
		let next
		const { isAuthenticated, oidc: cOidc} = context
		const oidc = new ResponseContext(this.config, req, res, next, this.transient)
		const returnTo = this.config.baseURL
		const logoutResponse = await oidc.logout({ returnTo, isAuthenticated, oidc: cOidc })
		const { returnURL } = logoutResponse
		const cookies = prepareCookies(logoutResponse.cookies)

		return {
			returnURL,
			cookies
		}
	}
}

function prepareCookies (cookies) {
	const skCookies = []

	// `${cookieName}=deleted; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly;`
	// `appSession=${jwt}; Path=/; Max-Age=${expiresIn}; HttpOnly;` // TODO: Set Secure
	_.forEach(_.values(cookies), (cookie) => {
		const { cookieName, value, attributes } = cookie
		let skCookie = `${cookieName}=${value}; `
		_.forEach(attributes, (value, key) => {
			if (value) skCookie += ` ${key}=${value};`
		})

		skCookies.push(skCookie)
	})

	return skCookies
}

export {
	AppSession
}
