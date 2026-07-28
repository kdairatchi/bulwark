import { readFileSync } from 'fs'
import { validateBetaReport } from '../src/shared/beta-report'

const file = process.argv[2]
if (!file) {
  console.error('Usage: npx tsx scripts/validate-beta-report.ts <report.json>')
  process.exit(2)
}

try {
  const report = JSON.parse(readFileSync(file, 'utf8')) as unknown
  const errors = validateBetaReport(report)
  if (errors.length > 0) {
    console.error(errors.map((error) => `- ${error}`).join('\n'))
    process.exit(1)
  }
  console.log(`Valid beta report: ${file}`)
} catch (error) {
  console.error(`Unable to read beta report: ${error instanceof Error ? error.message : String(error)}`)
  process.exit(1)
}
