import { generators } from 'openid-client'
import { JWKS, JWS, JWK } from 'jose'
import { signing as deriveKey } from './hkdf'
// import COOKIES from './cookies'

const header = { alg: 'HS256', b64: false, crit: ['b64'] }
const getPayload = (cookie, value) => Buffer.from(`${cookie}=${value}`)
const flattenedJWSFromCookie = (cookie, value, signature) => ({
	protected: Buffer.from(JSON.stringify(header))
		.toString('base64')
		.replace(/=/g, '')
		.replace(/\+/g, '-')
		.replace(/\//g, '_'),
	payload: getPayload(cookie, value),
	signature
})
const generateSignature = (cookie, value, key) => {
	const payload = getPayload(cookie, value)
	return JWS.sign.flattened(payload, key, header).signature
}
const verifySignature = (cookie, value, signature, keystore) => {
	try {
		return !!JWS.verify(
			flattenedJWSFromCookie(cookie, value, signature),
			keystore,
			{ algorithm: 'HS256', crit: ['b64'] }
		)
	} catch (err) {
		return false
	}
}
const getCookieValue = (cookie, value, keystore) => {
	if (!value) {
		return undefined
	}
	let signature;
	[value, signature] = value.split('.')
	if (verifySignature(cookie, value, signature, keystore)) {
		return value
	}

	return undefined
}

const generateCookieValue = (cookie, value, key) => {
	const signature = generateSignature(cookie, value, key)
	return `${value}.${signature}`
}

class TransientCookieHandler {
	constructor ({ secret, session, legacySameSiteCookie }) {
		let current
		this.cookies = []
		const secrets = Array.isArray(secret) ? secret : [secret]
		let keystore = new JWKS.KeyStore()
		secrets.forEach((secretString, i) => {
			const key = JWK.asKey(deriveKey(secretString))
			if (i === 0) {
				current = key
			}
			keystore.add(key)
		})

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

		// let value = getCookieValue(key, req[COOKIES][key], this.keyStore)
		let value = getCookieValue(key, req.cookies[key], this.keyStore)
		this.deleteCookie(key, res)

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
   */
	deleteCookie (cookieName) {
		const { domain, path } = this.sessionCookieConfig
		const attributes = {
			domain,
			expires: 'Thu, 01 Jan 1970 00:00:00 GMT',
			HttpOnly: true,
			path
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
