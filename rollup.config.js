import json from '@rollup/plugin-json'
import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import pkg from './package.json'

export default {
	input: 'src/main.js',
	output: [
		{
			file: 'dist/bundle.cjs',
			format: 'cjs'
		},
		{
			file: 'dist/bundle.mjs',
			format: 'es'
		}
	],
	plugins: [
		commonjs(),
		json(),
		resolve({

		})
	],
	external: Object.keys(pkg.dependencies || [])
}
