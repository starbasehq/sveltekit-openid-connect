/* eslint-disable no-prototype-builtins */
import _ from 'lodash'
import { strict as assert, AssertionError } from 'assert'
import {
	JWK,
	JWKS,
	JWE,
	errors
} from 'jose'
import crypto from 'crypto'
import { promisify } from 'util'
import getConfig from './config'
// import TransientCookieHandler from './transientHandler'
// import cookie from 'cookie'
// import COOKIES from './cookies'
import { prepareCookies } from './cookies'
import { encryption as deriveKey } from './hkdf'
import jwtDecode from 'jwt-decode'

const epoch = () => (Date.now() / 1000) | 0
const CHUNK_BYTE_SIZE = 4000
const { JOSEError } = errors

function attachSessionObject (req, sessionName, value) {
	Object.defineProperty(req, sessionName, {
		enumerable: true,
		get () {
			return value
		},
		set (arg) {
			if (arg === null || arg === undefined) {
				value = arg
			} else {
				throw new TypeError('session object cannot be reassigned')
			}
			// return undefined
		}
	})
}

function appSession (params) {
	let current
	const resCookies = {}
	const config = getConfig(params)

	const alg = 'dir'
	const enc = 'A256GCM'
	const secrets = Array.isArray(config.secret)
		? config.secret
		: [config.secret]
	const sessionName = config.session.name
	const cookieConfig = config.session.cookie
	const {
		absoluteDuration,
		rolling: rollingEnabled,
		rollingDuration
	} = config.session

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

	function encrypt (payload, headers) {
		return JWE.encrypt(payload, current, { alg, enc, ...headers })
	}

	function decrypt (jwe) {
		return JWE.decrypt(jwe, keystore, {
			complete: true,
			contentEncryptionAlgorithms: [enc],
			keyManagementAlgorithms: [alg]
		})
	}

	function calculateExp (iat, uat) {
		if (!rollingEnabled) {
			return iat + absoluteDuration
		}

		return Math.min(
			...[uat + rollingDuration, iat + absoluteDuration].filter(Boolean)
		)
	}

	function setCookie (
		req,
		res,
		{ uat = epoch(), iat = uat, exp = calculateExp(iat, uat) }
	) {
		const cookieOptions = {
			...cookieConfig,
			expires: cookieConfig.transient ? 0 : new Date(exp * 1000)
		}
		delete cookieOptions.transient
		if (!cookieOptions.path) cookieOptions.path = '/'

		// session was deleted or is empty, this matches all session cookies (chunked or unchunked)
		// and clears them, essentially cleaning up what we've set in the past that is now trash
		if (!req[sessionName] || !Object.keys(req[sessionName]).length) {
			console.log(
				'session was deleted or is empty, clearing all matching session cookies'
			)
			for (const cookieName of Object.keys(req.cookies)) {
				if (cookieName.match(`^${sessionName}(?:\\.\\d)?$`)) {
					// res.clearCookie(cookieName, {
					// 	domain: cookieOptions.domain,
					// 	path: cookieOptions.path
					// })
					const clearCookie = {
						cookieName,
						value: 'deleted',
						attributes: {
							domain: cookieOptions.domain,
							path: cookieOptions.path
						}
					}
					resCookies[cookieName] = clearCookie
				}
			}
		} else {
			// console.log(
			// 	'found session, creating signed session cookie(s) with name %o(.i)',
			// 	sessionName
			// )
			const value = encrypt(JSON.stringify(req[sessionName]), {
				iat,
				uat,
				exp
			})

			const chunkCount = Math.ceil(value.length / CHUNK_BYTE_SIZE)
			if (chunkCount > 1) {
				console.log('cookie size greater than %d, chunking', CHUNK_BYTE_SIZE)
				for (let i = 0; i < chunkCount; i++) {
					const chunkValue = value.slice(
						i * CHUNK_BYTE_SIZE,
						(i + 1) * CHUNK_BYTE_SIZE
					)
					const chunkCookieName = `${sessionName}.${i}`
					// res.cookie(chunkCookieName, chunkValue, cookieOptions)
					resCookies[chunkCookieName] = {
						cookieName: chunkCookieName,
						value: chunkValue,
						attributes: cookieOptions
					}
				}
			} else {
				// res.cookie(sessionName, value, cookieOptions)
				resCookies[sessionName] = {
					cookieName: sessionName,
					value,
					attributes: cookieOptions
				}
			}
		}
	}

	class CookieStore {
		async get (idOrVal) {
			const { protected: header, cleartext } = decrypt(idOrVal)
			return {
				header,
				data: JSON.parse(cleartext)
			}
		}

		async set (id, req, res, iat) {
			setCookie(req, res, iat)
		}
	}

	class CustomStore {
		constructor (store) {
			this._get = promisify(store.get).bind(store)
			this._set = promisify(store.set).bind(store)
			this._destroy = promisify(store.destroy).bind(store)
		}

		async get (id) {
			return this._get(id)
		}

		async set (
			id,
			req,
			res,
			{ uat = epoch(), iat = uat, exp = calculateExp(iat, uat) }
		) {
			if (!req[sessionName] || !Object.keys(req[sessionName]).length) {
				if (id) {
					res.clearCookie(sessionName, {
						domain: cookieConfig.domain,
						path: cookieConfig.path
					})
					await this._destroy(id)
				}
			} else {
				id = id || crypto.randomBytes(16).toString('hex')
				await this._set(id, {
					header: { iat, uat, exp },
					data: req[sessionName]
				})
				const cookieOptions = {
					...cookieConfig,
					expires: cookieConfig.transient ? 0 : new Date(exp * 1000)
				}
				delete cookieOptions.transient
				res.cookie(sessionName, id, cookieOptions)
			}
		}
	}

	const store = config.session.store
		? new CustomStore(config.session.store)
		: new CookieStore()

	// function extractData () {
	// 	console.log('extract data')
	// }

	return async (req, res, sessionData) => {
		if (req.hasOwnProperty(sessionName)) {
			console.log(
				'request object (req) already has %o property, this is indicative of a middleware setup problem',
				sessionName
			)
			throw new Error(
				`req[${sessionName}] is already set, did you run this middleware twice?`
			)
		}

		// req[COOKIES] = cookie.parse(req.get('cookie') || '')

		let iat
		let uat
		let exp
		let existingSessionValue

		try {
			if (req.cookies.hasOwnProperty(sessionName)) {
				// get JWE from unchunked session cookie
				// console.log('reading session from %s cookie', sessionName)
				existingSessionValue = req.cookies[sessionName]
			} else if (req.cookies.hasOwnProperty(`${sessionName}.0`)) {
				// get JWE from chunked session cookie
				// iterate all cookie names
				// match and filter for the ones that match sessionName.<number>
				// sort by chunk index
				// concat
				existingSessionValue = Object.entries(req.cookies)
					.map(([cookie, value]) => {
						const match = cookie.match(`^${sessionName}\\.(\\d+)$`)
						if (match) {
							return [match[1], value]
						}
					})
					.filter(Boolean)
					.sort(([a], [b]) => {
						return parseInt(a, 10) - parseInt(b, 10)
					})
					.map(([i, chunk]) => {
						console.log('reading session chunk from %s.%d cookie', sessionName, i)
						return chunk
					})
					.join('')
			}
			if (existingSessionValue) {
				// console.log('found existing session Value')
				const { header, data } = await store.get(existingSessionValue);
				({ iat, uat, exp } = header)

				// check that the existing session isn't expired based on options when it was established
				assert(
					exp > epoch(),
					'it is expired based on options when it was established'
				)

				// check that the existing session isn't expired based on current rollingDuration rules
				if (rollingDuration) {
					assert(
						uat + rollingDuration > epoch(),
						'it is expired based on current rollingDuration rules'
					)
				}

				// check that the existing session isn't expired based on current absoluteDuration rules
				if (absoluteDuration) {
					assert(
						iat + absoluteDuration > epoch(),
						'it is expired based on current absoluteDuration rules'
					)
				}

				attachSessionObject(req, sessionName, data)
			}
		} catch (err) {
			if (err instanceof AssertionError) {
				console.log('existing session was rejected because', err.message)
			} else if (err instanceof JOSEError) {
				console.log(
					'existing session was rejected because it could not be decrypted',
					err
				)
			} else {
				console.log('unexpected error handling session', err)
			}
		}

		if (!req.hasOwnProperty(sessionName) || !req[sessionName]) {
			attachSessionObject(req, sessionName, sessionData || {})
		}

		// await store.set(existingSessionValue, req, res, {
		// 	iat
		// })
		setCookie(req, res, { iat })

		const isExpired = req[sessionName].exp < new Date().getTime() / 1000

		return Object.assign(
			{ cookies: prepareCookies(_.values(resCookies)) },
			(!sessionData && !isExpired) && { oidc: req[sessionName] },
			(!sessionData && !isExpired) && { user: jwtDecode(req[sessionName].id_token) }
		)

		// const { end: origEnd } = res
		// res.end = async function resEnd (...args) {
		// 	try {
		// 		await store.set(existingSessionValue, req, res, {
		// 			iat
		// 		})
		// 		origEnd.call(res, ...args)
		// 	} catch (e) {
		// 		// need to restore the original `end` so that it gets
		// 		// called after `next(e)` calls the express error handling mw
		// 		res.end = origEnd
		// 		process.nextTick(() => next(e))
		// 	}
		// }

		// return next()
	}
}

export default appSession
