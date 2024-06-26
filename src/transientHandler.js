import { generators } from 'openid-client'
import {
	signCookie as generateCookieValue,
	verifyCookie as getCookieValue,
	getKeyStore
} from './crypto'

class TransientCookieHandler {
	constructor ({ secret, session, legacySameSiteCookie }) {
		let [current, keystore] = getKeyStore(secret);
		this.cookies = []

		if (keystore.size === 1) {
			keystore = current
		}
		this.currentKey = current
		this.keyStore = keystore
		this.sessionCookieConfig = (session && session.cookie) || {}
		this.legacySameSiteCookie = legacySameSiteCookie
	}

	cookie (key, value, attributes) {
		this.cookies[key] = {
			cookieName: key,
			value,
			attributes
		}
	}

	getCookies (key) {
		if (key) {
			return this.cookies[key]
		} else {
			return this.cookies
		}
	}

	/**
   * Set a cookie with a value or a generated nonce.
   *
   * @param {String} key Cookie name to use.
   * @param {Object} req Express Request object.
   * @param {Object} res Express Response object.
   * @param {Object} opts Options object.
   * @param {String} opts.sameSite SameSite attribute of "None," "Lax," or "Strict". Default is "None."
   * @param {String} opts.value Cookie value. Omit this key to store a generated value.
   * @param {Boolean} opts.legacySameSiteCookie Should a fallback cookie be set? Default is true.
   *
   * @return {String} Cookie value that was set.
   */
	store (
		key,
		req,
		res,
		{ sameSite = 'None', value = this.generateNonce() } = {}
	) {
		const isSameSiteNone = sameSite === 'None'
		const { domain, path, secure } = this.sessionCookieConfig
		const basicAttr = {
			httpOnly: true,
			secure,
			domain,
			path
		}

		{
			const cookieValue = generateCookieValue(key, value, this.currentKey)
			// Set the cookie with the SameSite attribute and, if needed, the Secure flag.
			this.cookie(key, cookieValue, {
				...basicAttr,
				sameSite,
				secure: isSameSiteNone ? true : basicAttr.secure
			})
		}

		if (isSameSiteNone && this.legacySameSiteCookie) {
			const cookieValue = generateCookieValue(
				`_${key}`,
				value,
				this.currentKey
			)
			// Set the fallback cookie with no SameSite or Secure attributes.
			this.cookie(`_${key}`, cookieValue, basicAttr)
		}

		return value
	}

	/**
   * Get a cookie value then delete it.
   *
   * @param {String} key Cookie name to use.
   * @param {Object} req Express Request object.
   * @param {Object} res Express Response object.
   *
   * @return {String|undefined} Cookie value or undefined if cookie was not found.
   */
	getOnce (key, req, res) {
		// if (!req[COOKIES]) {
		if (!req.cookies) {
			console.error('failed to find cookies')
			return undefined
		}
		console.debug('found cookies')
		const { secure, sameSite } = this.sessionCookieConfig

		// let value = getCookieValue(key, req[COOKIES][key], this.keyStore)
		let value = getCookieValue(key, req.cookies[key], this.keyStore)
		this.deleteCookie(key, res, { secure, sameSite });

		if (this.legacySameSiteCookie) {
			const fallbackKey = `_${key}`
			if (!value) {
				value = getCookieValue(
					fallbackKey,
					// req[COOKIES][fallbackKey],
					req.cookies[fallbackKey],
					this.keyStore
				)
			}
			this.deleteCookie(fallbackKey, res)
		}

		return value
	}

	/**
   * Generates a nonce value.
   *
   * @return {String}
   */
	generateNonce () {
		return generators.nonce()
	}

	/**
   * Generates a code_verifier value.
   *
   * @return {String}
   */
	generateCodeVerifier () {
		return generators.codeVerifier()
	}

	/**
   * Calculates a code_challenge value for a given codeVerifier
   *
   * @param {String} codeVerifier Code Verifier to calculate the code_challenge value from.
   *
   * @return {String}
   */
	calculateCodeChallenge (codeVerifier) {
		return generators.codeChallenge(codeVerifier)
	}

	/**
   * Clears the cookie from the browser by setting an empty value and an expiration date in the past
   *
   * @param {String} name Cookie name
   * @param {Object} res Express Response object
   * @param {Object?} opts Optional SameSite and Secure cookie options for modern browsers
   */
	deleteCookie (cookieName, opts = {}) {
		const { domain, path } = this.sessionCookieConfig
		const { sameSite, secure } = opts;
		const attributes = {
			domain,
			expires: 'Thu, 01 Jan 1970 00:00:00 GMT',
			HttpOnly: true,
			path,
			sameSite,
			secure
		}
		// res.clearCookie(name, {
		// 	domain,
		// 	path
		// })
		// if (!res.cookies) res.cookies = []
		// `${cookieName}=deleted; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly;`
		// `appSession=${jwt}; Path=/; Max-Age=${expiresIn}; HttpOnly;` // TODO: Set Secure
		// let skCookie = `${cookieName}=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; `
		// if (path) skCookie += `path=${path}`
		// if (domain) skCookie += `domain=${domain}`
		// res.cookies.push(skCookie)
		this.cookie(`${cookieName}`, 'deleted', attributes)
	}
}

export default TransientCookieHandler
