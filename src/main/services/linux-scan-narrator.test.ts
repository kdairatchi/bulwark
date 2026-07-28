import { describe, it, expect } from 'vitest'
import { linuxEnvironmentNote, linuxPathFocus, linuxSurfaceFocus } from './linux-scan-narrator'

describe('linux-scan-narrator', () => {
  it('nicknames common Linux drop zones', () => {
    expect(linuxPathFocus('/tmp/evil')).toMatch(/volatile/i)
    expect(linuxPathFocus('/dev/shm/x')).toMatch(/memory/i)
    expect(linuxPathFocus('/usr/local/bin')).toMatch(/local installs/i)
  })

  it('explains ClamAV absence clearly', () => {
    const note = linuxEnvironmentNote({ step: 'defender', clamAvailable: false })
    expect(note).toMatch(/not installed/i)
    expect(note).toMatch(/clamav/i)
  })

  it('keeps a unique surface focus label per step', () => {
    expect(linuxSurfaceFocus('persistence')).toMatch(/Autostart/i)
    expect(linuxSurfaceFocus('discovering')).toMatch(/drop zones/i)
  })

  it('does not invent findings during discovery', () => {
    const note = linuxEnvironmentNote({ step: 'discovering', path: '/tmp' })
    expect(note).toMatch(/Mapping|Walking/i)
    expect(note).not.toMatch(/threat found|infected/i)
  })
})
