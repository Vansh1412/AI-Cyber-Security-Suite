import * as esbuild from 'esbuild'
import { copyFileSync, mkdirSync, cpSync, existsSync } from 'fs'
import { resolve, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const isWatch = process.argv.includes('--watch')

const baseConfig = {
  bundle: true,
  platform: 'browser',
  target: 'es2022',
  format: 'iife',
  minify: !isWatch,
  sourcemap: isWatch ? 'inline' : false,
  define: {
    'process.env.NODE_ENV': isWatch ? '"development"' : '"production"',
  },
}

// Ensure dist dirs exist
mkdirSync('dist/background', { recursive: true })
mkdirSync('dist/popup', { recursive: true })
mkdirSync('dist/content', { recursive: true })
mkdirSync('dist/assets', { recursive: true })

async function build() {
  // 1. Bundle service worker
  await esbuild.build({
    ...baseConfig,
    entryPoints: ['background/service-worker.ts'],
    outfile: 'dist/background/service-worker.js',
    // Service workers cannot be bundled as IIFE in MV3 — use ESM
    format: 'esm',
  })

  // 2. Bundle popup
  await esbuild.build({
    ...baseConfig,
    entryPoints: ['popup/popup.ts'],
    outfile: 'dist/popup/popup.js',
    format: 'iife',
  })

  // 3. Bundle content script
  await esbuild.build({
    ...baseConfig,
    entryPoints: ['content/content.ts'],
    outfile: 'dist/content/content.js',
    format: 'iife',
  })

  // 4. Copy static files
  copyFileSync('manifest.json', 'dist/manifest.json')
  copyFileSync('popup/popup.html', 'dist/popup/popup.html')
  copyFileSync('popup/popup.css', 'dist/popup/popup.css')

  // Copy icons
  if (existsSync('assets')) {
    cpSync('assets', 'dist/assets', { recursive: true })
  }

  console.log('✅ Extension built to dist/')
}

if (isWatch) {
  const contexts = await Promise.all([
    esbuild.context({ ...baseConfig, format: 'esm', entryPoints: ['background/service-worker.ts'], outfile: 'dist/background/service-worker.js' }),
    esbuild.context({ ...baseConfig, format: 'iife', entryPoints: ['popup/popup.ts'], outfile: 'dist/popup/popup.js' }),
    esbuild.context({ ...baseConfig, format: 'iife', entryPoints: ['content/content.ts'], outfile: 'dist/content/content.js' }),
  ])
  await Promise.all(contexts.map(ctx => ctx.watch()))
  console.log('👀 Watching for changes...')
} else {
  build().catch(() => process.exit(1))
}
