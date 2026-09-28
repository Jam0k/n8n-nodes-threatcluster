// Copies node and credential icons into dist/ next to the compiled JS, the
// way n8n's community-node starter does it. tsc only emits .js/.d.ts, and
// n8n resolves `icon: 'file:threatcluster.svg'` relative to the compiled node.
const path = require('path');
const { src, dest } = require('gulp');

function copyIcons() {
	const nodeSource = path.resolve('nodes', '**', '*.{png,svg}');
	const nodeDestination = path.resolve('dist', 'nodes');
	src(nodeSource).pipe(dest(nodeDestination));

	const credSource = path.resolve('credentials', '**', '*.{png,svg}');
	const credDestination = path.resolve('dist', 'credentials');
	return src(credSource, { allowEmpty: true }).pipe(dest(credDestination));
}

exports['build:icons'] = copyIcons;
