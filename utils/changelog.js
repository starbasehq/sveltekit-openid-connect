'use strict'

/**
 * Update CHANGELOG.md automatically - https://github.com/conventional-changelog/standard-version
 * 1. Group by git tags
 * 2. Group by commit types
 */
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import standardVersion from 'standard-version'
// Process CLI arguments
const args = yargs(hideBin(process.argv))
	.usage('Usage: $0')
	.help('h')
	.options({
		dryRun: {
			type: 'boolean',
			default: false
		},
		skipBump: {
			type: 'boolean',
			default: false
		},
		skipCommit: {
			type: 'boolean',
			default: false
		},
		skipTag: {
			type: 'boolean',
			default: false
		},
		firstRelease: {
			type: 'boolean',
			default: false
		},
		preRelease: {
			type: 'string',
			default: ''
		},
		noVerify: {
			type: 'boolean',
			default: true,
			description: 'Disable commit format verification'
		},
		signCommit: {
			type: 'boolean',
			default: true,
			description: 'Sign the commits created'
		}
	})
	.parse(process.argv)

const { dryRun, skipBump, skipCommit, skipTag, firstRelease, preRelease, signCommit, noVerify } = args

const options = {
	dryRun,
	firstRelease,
	noVerify,
	preRelease,
	sign: signCommit,
	skip: {
		bump: skipBump,
		commit: skipCommit,
		tag: skipTag
	}
}
const specProps = getSchema()

Object.keys(specProps).forEach(propertyKey => {
	const property = specProps[propertyKey]
	options[propertyKey] = property.default
})

standardVersion(options)
	.then(() => {
		console.log('Finished updating CHANGELOG.md')
	}).catch(err => {
		console.error(`Update CHANGELOG.md failed with message: ${err.message}`)
	})

function getSchema () {
	return {
		header: {
			type: 'string',
			description: 'A string to be used as the main header section of the CHANGELOG.',
			default: '# Changelog\n'
		},
		types: {
			description: 'An array of `type` objects representing the explicitly supported commit message types, and whether they should show up in generated `CHANGELOG`s.',
			type: 'array',
			items: {
				$ref: '#/definitions/type'
			},
			default: [
				{ type: 'feat', section: 'Features' }, //
				{ type: 'feature', section: 'Features' }, //
				{ type: 'fix', section: 'Bug Fixes' }, //
				{ type: 'hotfix', section: 'Bug Fixes' }, //
				{ type: 'improvement', section: 'Improvements' },
				{ type: 'test', section: 'Tests' },
				{ type: 'build', section: 'Build System' }, //
				{ type: 'ci', section: 'CICD' }, //
				{ type: 'chore', section: 'Chore' }, //
				{ type: 'perf', section: 'Performance' }, //
				{ type: 'refactor', section: 'Refactor' },
				{ type: 'revert', section: 'Revert' },
				{ type: 'style', section: 'Style' },
				{ type: 'docs', section: '📝 Docs' }, //
				{ type: 'release', hidden: true }
			]
		},
		preMajor: {
			type: 'boolean',
			description: 'Boolean indicating whether or not the action being run (generating CHANGELOG, recommendedBump, etc.) is being performed for a pre-major release (<1.0.0).\n This config setting will generally be set by tooling and not a user.',
			default: false
		},
		commitUrlFormat: {
			type: 'string',
			description: 'A URL representing a specific commit at a hash.',
			default: '{{host}}/{{owner}}/{{repository}}/commit/{{hash}}'
		},
		compareUrlFormat: {
			type: 'string',
			description: 'A URL representing the comparison between two git SHAs.',
			default: '{{host}}/{{owner}}/{{repository}}/compare/{{previousTag}}...{{currentTag}}'
		},
		issueUrlFormat: {
			type: 'string',
			description: 'A URL representing the issue format (allowing a different URL format to be swapped in for Gitlab, Bitbucket, etc).',
			default: '{{host}}/{{owner}}/{{repository}}/issues/{{id}}'
		},
		userUrlFormat: {
			type: 'string',
			description: "A URL representing the a user's profile URL on GitHub, Gitlab, etc. This URL is used for substituting @bcoe with https://github.com/bcoe in commit messages.",
			default: '{{host}}/{{user}}'
		},
		releaseCommitMessageFormat: {
			type: 'string',
			description: 'A string to be used to format the auto-generated release commit message.',
			default: 'release(RELEASE): v{{currentTag}}'
		},
		issuePrefixes: {
			type: 'array',
			items: {
				type: 'string'
			},
			description: 'An array of prefixes used to detect references to issues',
			default: ['#', 'STB-', 'STBC-', 'STBO-']
		}
	}
}
