module.exports = {
	extends: ['@commitlint/config-conventional'],
	rules: {
		'header-max-length': [2, 'always', 100],
		'scope-case': [2, 'always', 'upper-case'],
		'subject-case': [
				2,
				'never',
				['sentence-case', 'start-case', 'pascal-case', 'upper-case']
		],
		'subject-empty': [2, 'never'],
		'type-case': [2, 'always', ['lower-case', 'upper-case']],
		'type-empty': [2, 'never'],
		'type-enum': [
			2,
			'always',
			[
				'build',
				'chore',
				'ci',
				'docs',
				'feat',
				'fix',
				'hotfix',
				'improvement',
				'perf',
				'refactor',
				'revert',
				'style',
				'test',
				'feature',
				'release'
			]
		]
	},
}
