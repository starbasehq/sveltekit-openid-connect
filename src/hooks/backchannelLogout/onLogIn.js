import { promisify } from 'util'
import getClient from '../../client'

// Remove any Back-Channel Logout tokens for this `sub`
export default async (req, config) => {
	const {
		issuer: { issuer },
	} = await getClient(config);
	const { session, backchannelLogout } = config;
	const store = (backchannelLogout && backchannelLogout.store) || session.store;
	const destroy = promisify(store.destroy).bind(store);
	await destroy(`${issuer}|${req.oidc.idTokenClaims.sub}`);
};
