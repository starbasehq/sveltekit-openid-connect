import {
	JWK,
	JWKS,
	JWE
} from 'jose'
import { jwtDecode } from 'jwt-decode'
import getConfig from './config'
import { encryption as deriveKey } from './hkdf'

let current

const alg = 'dir'
const enc = 'A256GCM'

export default class TokenUtils {
	constructor (params) {
		this.keystore = new JWKS.KeyStore()
		this.config = getConfig(params)
		this.secrets = Array.isArray(this.config.secret)
		? this.config.secret
		: [this.config.secret]
		let current
		this.secrets.forEach((secretString, i) => {
			const key = JWK.asKey(deriveKey(secretString))
			if (i === 0) {
				current = key
			}
			this.keystore.add(key)
		})

		if (this.keystore.size === 1) {
			this.keystore = current
		}
		const {
			absoluteDuration,
			rolling: rollingEnabled,
			rollingDuration
		} = this.config.session
		this.absoluteDuration = absoluteDuration
		this.rollingEnabled = rollingEnabled
		this.rollingDuration = rollingDuration
	}

	encrypt (payload, headers) {
		return JWE.encrypt(payload, current, { alg, enc, ...headers })
	}

	decrypt (jwe) {
		return JWE.decrypt(jwe, this.keystore, {
			complete: true,
			contentEncryptionAlgorithms: [enc],
			keyManagementAlgorithms: [alg]
		})
	}

	getAccessToken (token) {
		const payload = this.parse(token)
		return payload.access_token
	}

	getIdToken (eToken) {
		return this.decode(eToken)
	}

	parse (token) {
		return JSON.parse(this.decrypt(token).cleartext)
	}

	decode ({ id_token, token }) {
		if (token) {
			id_token = this.parse(token).id_token
		}
		return jwtDecode(id_token)
	}

	calculateExp (iat, uat) {
		if (!this.rollingEnabled) {
			return iat + this.absoluteDuration
		}

		return Math.min(
			...[uat + this.rollingDuration, iat + this.absoluteDuration].filter(Boolean)
		)
	}

	isExpired ({ exp, token }) {
		try {
			if (token) {
				exp = this.decrypt(token).protected.exp
			}
			return exp < new Date().getTime() / 1000
		} catch (err) {
			return true
		}
	}
}
