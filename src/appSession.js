/* eslint-disable no-prototype-builtins */
import _ from 'lodash'
import { strict as assert, AssertionError } from 'assert'
import {
	JWE,
	errors
} from 'jose'
import * as jose from 'jose'
import { promisify } from 'util'
import getConfig from './config'
// import TransientCookieHandler from './transientHandler'
import cookie from 'cookie'
// import COOKIES from './cookies'
import { prepareCookies } from './cookies'
import { getKeyStore, verifyCookie, signCookie } from './crypto'


const { JOSEError } = errors

const epoch = () => (Date.now() / 1000) | 0
const MAX_COOKIE_SIZE = 4096;

const REASSIGN = Symbol('reassign');
const REGENERATED_SESSION_ID = Symbol('regenerated_session_id');

function attachSessionObject (req, sessionName, value) {
	Object.defineProperty(req, sessionName, {
		enumerable: true,
		get () {
			return value
		},
		set (arg) {
			if (arg === null || arg === undefined || arg[REASSIGN]) {
				value = arg
			} else {
				throw new TypeError('session object cannot be reassigned')
			}
			return undefined
		}
	})
}

async function regenerateSessionStoreId(req, config) {
	if (config.session.store) {
		req[REGENERATED_SESSION_ID] = await config.session.genid(req);
	}
}

function replaceSession(req, session, config) {
	session[REASSIGN] = true;
	req[config.session.name] = session;
}

function appSession (params) {
	const resCookies = {}
	const config = getConfig(params)

	const alg = 'dir'
	const enc = 'A256GCM'
	const sessionName = config.session.name
	const cookieConfig = config.session.cookie
	const {
		genid: generateId,
		absoluteDuration,
		rolling: rollingEnabled,
		rollingDuration,
		signSessionStoreCookie,
		requireSignedSessionStoreCookie,
	} = config.session

	const { transient: emptyTransient, ...emptyCookieOptions } = cookieConfig;
		emptyCookieOptions.expires = emptyTransient ? 0 : new Date();
		emptyCookieOptions.path = emptyCookieOptions.path || '/';

	const emptyCookie = cookie.serialize(
		`${sessionName}.0`,
		'',
		emptyCookieOptions
	);
	const cookieChunkSize = MAX_COOKIE_SIZE - emptyCookie.length;

	let [current, keystore] = getKeyStore(config.secret, true);
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
		const cookies = req.cookies;
		const { transient: cookieTransient, ...cookieOptions } = cookieConfig;
		cookieOptions.expires = cookieTransient ? 0 : new Date(exp * 1000);
		if (!cookieOptions.path) cookieOptions.path = '/' // TODO: Is this a starbase customization?

		// session was deleted or is empty, this matches all session cookies (chunked or unchunked)
		// and clears them, essentially cleaning up what we've set in the past that is now trash
		if (!req[sessionName] || !Object.keys(req[sessionName]).length) {
			console.warn(
				'session was deleted or is empty, clearing all matching session cookies'
			)
			for (const cookieName of Object.keys(cookies)) { // need req.cookies instead?
				if (cookieName.match(`^${sessionName}(?:\\.\\d)?$`)) {
					// res.clearCookie(cookieName, {
					// 	domain: cookieOptions.domain,
					// 	path: cookieOptions.path
					// })
					const clearCookieObj = {
						cookieName,
						value: 'deleted',
						attributes: {
							domain: cookieOptions.domain,
							path: cookieOptions.path
						}
					}
					resCookies[cookieName] = clearCookieObj
					clearCookie(cookieName, res) // This potentially replaces the above
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

			const chunkCount = Math.ceil(value.length / cookieChunkSize)
			if (chunkCount > 1) {
				console.debug('cookie size greater than %d, chunking', cookieChunkSize)
				for (let i = 0; i < chunkCount; i++) {
					const chunkValue = value.slice(
						i * cookieChunkSize,
						(i + 1) * cookieChunkSize
					)
					const chunkCookieName = `${sessionName}.${i}`
					// res.cookie(chunkCookieName, chunkValue, cookieOptions)
					resCookies[chunkCookieName] = {
						cookieName: chunkCookieName,
						value: chunkValue,
						attributes: cookieOptions
					}
				}
				if (sessionName in cookies) {
					console.debug('replacing non chunked cookie with chunked cookies');
					clearCookie(sessionName, res);
				}
			} else {
				// res.cookie(sessionName, value, cookieOptions)
				resCookies[sessionName] = {
					cookieName: sessionName,
					value,
					attributes: cookieOptions
				}
				for (const cookieName of Object.keys(cookies)) {
					console.debug('replacing chunked cookies with non chunked cookies');
					if (cookieName.match(`^${sessionName}\\.\\d$`)) {
						clearCookie(cookieName, res);
					}
				}
			}
		}
	}

	function clearCookie(name, res) {
		const { domain, path, sameSite, secure } = cookieConfig
		res.clearCookie(name, {
			domain,
			path,
			sameSite,
			secure
		})
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

			let [current, keystore] = getKeyStore(config.secret)
			if (keystore.size === 1) {
				keystore = current
			}
			this._keyStore = keystore
			this._current = current
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
			const hasPrevSession = !!req.cookies[sessionName]
			const replacingPrevSession = !!req[REGENERATED_SESSION_ID]
			const hasCurrentSession =
				req[sessionName] && Object.keys(req[sessionName]).length
			if (hasPrevSession && (replacingPrevSession || !hasCurrentSession)) {
				await this._destroy(id);
			}
			if (hasCurrentSession) {
				await this._set(req[REGENERATED_SESSION_ID] || id, {
					header: { iat, uat, exp },
					data: req[sessionName],
					cookie: {
						expires: exp * 1000,
						maxAge: exp * 1000 - Date.now(),
					},
				});
			}
			// if (!req[sessionName] || !Object.keys(req[sessionName]).length) {
			// 	if (id) {
			// 		res.clearCookie(sessionName, {
			// 			domain: cookieConfig.domain,
			// 			path: cookieConfig.path
			// 		})
			// 		await this._destroy(id)
			// 	}
			// } else {
			// 	id = id || crypto.randomBytes(16).toString('hex')
			// 	await this._set(id, {
			// 		header: { iat, uat, exp },
			// 		data: req[sessionName]
			// 	})
			// 	const cookieOptions = {
			// 		...cookieConfig,
			// 		expires: cookieConfig.transient ? 0 : new Date(exp * 1000)
			// 	}
			// 	delete cookieOptions.transient
			// 	res.cookie(sessionName, id, cookieOptions)
			// }
		}

		getCookie(req) {
			if (signSessionStoreCookie) {
				const verified = verifyCookie(
					sessionName,
					req.cookies[sessionName],
					this._keyStore
				)
				if (requireSignedSessionStoreCookie) {
					return verified
				}
				return verified || req.cookies[sessionName]
			}
			return req.cookies[sessionName]
		}

		setCookie(
			id,
			req,
			res,
			{ uat = epoch(), iat = uat, exp = calculateExp(iat, uat) }
		) {
			if (!req[sessionName] || !Object.keys(req[sessionName]).length) {
				if (req.cookies[sessionName]) {
					clearCookie(sessionName, res);
				}
			} else {
				const cookieOptions = {
					...cookieConfig,
					expires: cookieConfig.transient ? 0 : new Date(exp * 1000),
				}
				delete cookieOptions.transient;
				let value = id;
				if (signSessionStoreCookie) {
					value = signCookie(sessionName, id, this._current)
				}
				res.cookie(sessionName, value, cookieOptions)
			}
		}
	}

	const isCustomStore = !!config.session.store;
	const store = isCustomStore
		? new CustomStore(config.session.store)
		: new CookieStore()

	// function extractData () {
	// 	console.log('extract data')
	// }

	return async (req, res, sessionData) => {
		if (req.hasOwnProperty(sessionName)) {
			console.warn(
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
				// existingSessionValue = req.cookies[sessionName] // TODO: Was this starbase custom?
				existingSessionValue = store.getCookie(req);
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
						console.debug('reading session chunk from %s.%d cookie', sessionName, i)
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
				console.error('existing session was rejected because', err.message)
			} else if (err instanceof JOSEError) {
				console.error(
					'existing session was rejected because it could not be decrypted',
					err
				)
			} else {
				console.error('unexpected error handling session', err)
			}
		}

		if (!req.hasOwnProperty(sessionName) || !req[sessionName]) {
			attachSessionObject(req, sessionName, sessionData || {})
		}

		// if (isCustomStore) {
		// 	const id = existingSessionValue || (await generateId(req))
		// 	// TODO: is this needed? from 2.17.1
		// 	// onHeaders(res, () =>
		// 	// 	store.setCookie(req[REGENERATED_SESSION_ID] || id, req, res, { iat })
		// }

		// await store.set(existingSessionValue, req, res, {
		// 	iat
		// })
		setCookie(req, res, { iat })

		const isExpired = req[sessionName].exp < new Date().getTime() / 1000

		return Object.assign(
			{ cookies: prepareCookies(_.values(resCookies)) },
			(!sessionData && !isExpired) && { oidc: req[sessionName] },
			(!sessionData && !isExpired) && { user: jose.JWT.decode(req[sessionName].id_token) }
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
export { regenerateSessionStoreId, replaceSession }
