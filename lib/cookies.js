import _ from 'lodash'
const COOKIES = Symbol('cookies')

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

export default COOKIES
export {
	prepareCookies
}
