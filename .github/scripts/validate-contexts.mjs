import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')
const SKIP = new Set(['.git', '.github', 'node_modules', '.claude'])
const L0_MAX = 120

function parseFrontmatter(content) {
  const match = content.match(/^---\n([\s\S]*?)\n---/)
  if (!match) return null
  const fm = {}
  for (const line of match[1].split('\n')) {
    const [key, ...rest] = line.split(':')
    if (key && rest.length) fm[key.trim()] = rest.join(':').trim()
  }
  return fm
}

const dirs = fs.readdirSync(ROOT, { withFileTypes: true })
  .filter(d => d.isDirectory() && !SKIP.has(d.name))

let errors = 0

for (const dir of dirs) {
  const contextFile = path.join(ROOT, dir.name, 'CONTEXT.md')
  const label = `${dir.name}/CONTEXT.md`

  if (!fs.existsSync(contextFile)) {
    console.error(`[FAIL] ${dir.name}/ — missing CONTEXT.md`)
    errors++
    continue
  }

  const content = fs.readFileSync(contextFile, 'utf8')

  if (!content.match(/^---\n[\s\S]*?\n---/)) {
    console.error(`[FAIL] ${label} — malformed or missing frontmatter`)
    errors++
    continue
  }

  const fm = parseFrontmatter(content)

  if (!fm) {
    console.error(`[FAIL] ${label} — could not parse frontmatter`)
    errors++
    continue
  }

  // name
  if (!fm.name) {
    console.error(`[FAIL] ${label} — missing required field: name`)
    errors++
  } else if (fm.name !== dir.name) {
    console.error(`[FAIL] ${label} — name "${fm.name}" does not match folder name "${dir.name}"`)
    errors++
  }

  // l0
  if (!fm.l0) {
    console.error(`[FAIL] ${label} — missing required field: l0`)
    errors++
  } else {
    if (fm.l0 === '>' || fm.l0 === '|') {
      console.error(`[FAIL] ${label} — l0 must be a single inline string, not a YAML block scalar`)
      errors++
    } else if (fm.l0.length > L0_MAX) {
      console.error(`[FAIL] ${label} — l0 exceeds ${L0_MAX} characters (${fm.l0.length})`)
      errors++
    }
  }

  // L1 and L2 sections
  if (!content.includes('## L1')) {
    console.error(`[FAIL] ${label} — missing ## L1 section`)
    errors++
  }

  if (!content.includes('## L2')) {
    console.error(`[FAIL] ${label} — missing ## L2 section`)
    errors++
  }

  if (errors === 0) {
    console.log(`[OK]   ${label}`)
  }
}

if (errors > 0) {
  console.error(`\n${errors} error(s) found — fix them before merging.`)
  process.exit(1)
} else {
  console.log('\nAll contexts valid.')
}
