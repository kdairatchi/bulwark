#!/usr/bin/env tsx
// ─── Rules Validation Script ──────────────────────────────────
// Validates all JSON rule files against the schema.
// Run: npx tsx src/main/rules/validate.ts
// Exits 0 if all valid, 1 if any errors found.

import Ajv from 'ajv'
import { readFileSync, readdirSync } from 'fs'
import path from 'path'

const RULES_DIR = path.resolve(__dirname, '..', '..', '..', 'rules')
const SCHEMA_PATH = path.join(RULES_DIR, 'schema', 'rules.schema.json')
const PLATFORMS = ['win32', 'darwin', 'linux'] as const

const VALID_VARS: Record<string, Set<string>> = {
  win32: new Set(['HOME', 'LOCALAPPDATA', 'APPDATA', 'WINDIR', 'PROGRAMDATA', 'PROGRAMFILES', 'PROGRAMFILES_X86', 'TMPDIR']),
  darwin: new Set(['HOME', 'LIBRARY', 'CACHES', 'APP_SUPPORT', 'TMPDIR']),
  linux: new Set(['HOME', 'CONFIG', 'CACHE', 'LOCAL_SHARE', 'TMPDIR']),
}

const EXPECTED_FILES = ['system.json', 'browsers.json', 'apps.json', 'gaming.json', 'gpu-cache.json', 'steam.json', 'databases.json', 'misc.json']

let errors = 0

function error(msg: string): void {
  console.error(`  ✗ ${msg}`)
  errors++
}

function ok(msg: string): void {
  console.log(`  ✓ ${msg}`)
}

// Load and compile schema
const schema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf-8'))
const ajv = new Ajv({ allErrors: true })
const validate = ajv.compile(schema)

function extractVars(obj: unknown): string[] {
  const vars: string[] = []
  JSON.stringify(obj).replace(/\$\{([A-Z0-9_]+)\}/g, (_match, name) => {
    vars.push(name)
    return ''
  })
  return vars
}

for (const platform of PLATFORMS) {
  console.log(`\n${platform}:`)
  const platformDir = path.join(RULES_DIR, platform)
  const files = readdirSync(platformDir).filter((f) => f.endsWith('.json'))

  // Check all expected files exist
  for (const expected of EXPECTED_FILES) {
    if (!files.includes(expected)) {
      error(`missing ${expected}`)
    }
  }

  for (const file of files) {
    const filePath = path.join(platformDir, file)

    // Parse JSON
    let data: unknown
    try {
      data = JSON.parse(readFileSync(filePath, 'utf-8'))
    } catch (e) {
      error(`${file}: invalid JSON — ${(e as Error).message}`)
      continue
    }

    // Schema validation
    const valid = validate(data)
    if (!valid) {
      const msgs = validate.errors?.map((e) => `${e.instancePath} ${e.message}`).join('; ')
      error(`${file}: schema validation failed — ${msgs}`)
    } else {
      ok(`${file} passes schema`)
    }

    // Variable validation
    const vars = extractVars(data)
    const validSet = VALID_VARS[platform]
    for (const v of vars) {
      if (!validSet.has(v)) {
        error(`${file}: unknown template variable \${${v}}`)
      }
    }

    // Unique ID checks for app-style files
    if (file === 'apps.json' || file === 'gaming.json' || file === 'gpu-cache.json') {
      const apps = (data as { apps: Array<{ id: string }> }).apps
      const ids = apps.map((a) => a.id)
      const dupes = ids.filter((id, i) => ids.indexOf(id) !== i)
      if (dupes.length > 0) {
        error(`${file}: duplicate IDs: ${dupes.join(', ')}`)
      }
    }

    // Unique label checks for databases
    if (file === 'databases.json') {
      const targets = (data as { targets: Array<{ label: string }> }).targets
      const labels = targets.map((t) => t.label)
      const dupes = labels.filter((l, i) => labels.indexOf(l) !== i)
      if (dupes.length > 0) {
        error(`${file}: duplicate labels: ${dupes.join(', ')}`)
      }
    }
  }
}

// Security catalogs (LotL grep + curated KEV) — separate schemas from cleaner rules.
console.log('\nsecurity:')
{
  const lolSchemaPath = path.join(RULES_DIR, 'schema', 'lolbins.schema.json')
  const lolPath = path.join(RULES_DIR, 'security', 'lolbins.json')
  try {
    const lolSchema = JSON.parse(readFileSync(lolSchemaPath, 'utf-8'))
    const lolValidate = ajv.compile(lolSchema)
    const lolData = JSON.parse(readFileSync(lolPath, 'utf-8'))
    if (!lolValidate(lolData)) {
      const msgs = lolValidate.errors?.map((e) => `${e.instancePath} ${e.message}`).join('; ')
      error(`lolbins.json: schema validation failed — ${msgs}`)
    } else {
      const ids = (lolData.rules as Array<{ id: string }>).map((r) => r.id)
      const dupes = ids.filter((id, i) => ids.indexOf(id) !== i)
      if (dupes.length) error(`lolbins.json: duplicate rule ids: ${dupes.join(', ')}`)
      else ok(`lolbins.json passes schema (${ids.length} rules)`)
    }
  } catch (e) {
    error(`lolbins.json: ${(e as Error).message}`)
  }

  const kevSchemaPath = path.join(RULES_DIR, 'schema', 'kev.schema.json')
  const kevPath = path.join(RULES_DIR, 'security', 'kev.json')
  try {
    const kevSchema = JSON.parse(readFileSync(kevSchemaPath, 'utf-8'))
    const kevValidate = ajv.compile(kevSchema)
    const kevData = JSON.parse(readFileSync(kevPath, 'utf-8'))
    if (!kevValidate(kevData)) {
      const msgs = kevValidate.errors?.map((e) => `${e.instancePath} ${e.message}`).join('; ')
      error(`kev.json: schema validation failed — ${msgs}`)
    } else {
      const ids = (kevData.entries as Array<{ cveId: string }>).map((e) => e.cveId)
      // Duplicate CVE IDs can appear across products — allow, but require unique cveId+product pairs
      const pairs = (kevData.entries as Array<{ cveId: string; product: string }>).map(
        (e) => `${e.cveId}|${e.product}`,
      )
      const dupes = pairs.filter((p, i) => pairs.indexOf(p) !== i)
      if (dupes.length) error(`kev.json: duplicate cveId+product: ${dupes.join(', ')}`)
      else ok(`kev.json passes schema (${ids.length} entries)`)
    }
  } catch (e) {
    error(`kev.json: ${(e as Error).message}`)
  }

  const advisorySchemaPath = path.join(RULES_DIR, 'schema', 'vendor-advisories.schema.json')
  const advisoryPath = path.join(RULES_DIR, 'security', 'vendor-advisories.json')
  try {
    const advisorySchema = JSON.parse(readFileSync(advisorySchemaPath, 'utf-8'))
    const advisoryValidate = ajv.compile(advisorySchema)
    const advisoryData = JSON.parse(readFileSync(advisoryPath, 'utf-8'))
    if (!advisoryValidate(advisoryData)) {
      const msgs = advisoryValidate.errors?.map((e) => `${e.instancePath} ${e.message}`).join('; ')
      error(`vendor-advisories.json: schema validation failed — ${msgs}`)
    } else {
      const ids = (advisoryData.entries as Array<{ id: string }>).map((e) => e.id)
      const dupes = ids.filter((id, i) => ids.indexOf(id) !== i)
      if (dupes.length) error(`vendor-advisories.json: duplicate ids: ${dupes.join(', ')}`)
      else ok(`vendor-advisories.json passes schema (${ids.length} entries)`)
    }
  } catch (e) {
    error(`vendor-advisories.json: ${(e as Error).message}`)
  }
}

console.log('')
if (errors > 0) {
  console.error(`✗ ${errors} error(s) found`)
  process.exit(1)
} else {
  console.log('✓ All rule files are valid')
  process.exit(0)
}
