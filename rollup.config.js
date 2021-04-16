import json from '@rollup/plugin-json'
// import { terser } from 'rollup-plugin-terser'
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
		// {
		// 	file: 'dist/bundle.min.js',
		// 	format: 'iife',
		// 	name: 'version',
		// 	plugins: [terser()]
		// },
		{
			file: 'dist/bundle.js',
			format: 'es'
		},
		// {
		// 	file: 'dist/bundle.min.mjs',
		// 	format: 'es',
		// 	plugins: [terser()]
		// }
	],
	plugins: [
		commonjs(),
		json(),
		resolve({

		})
	],
	external: Object.keys(pkg.dependencies || [])
}
