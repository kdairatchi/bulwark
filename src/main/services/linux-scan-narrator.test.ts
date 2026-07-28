import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { linuxEnvironmentNote, linuxPathFocus, linuxSurfaceFocus } from './linux-scan-narrator'

describe('linux-scan-narrator', () => {
  const prevHome = process.env.HOME

  beforeEach(() => {
    process.env.HOME = '/home/tester'
  })

  afterEach(() => {
    if (prevHome === undefined) delete process.env.HOME
    else process.env.HOME = prevHome
  })

  it('nicknames common Linux drop zones', () => {
    expect(linuxPathFocus('/tmp/evil')).toMatch(/volatile/i)
    expect(linuxPathFocus('/dev/shm/x')).toMatch(/memory/i)
    expect(linuxPathFocus('/usr/local/bin')).toMatch(/local installs/i)
  })

  it('nicknames HOME-relative paths', () => {
    expect(linuxPathFocus('/home/tester/Downloads/payload')).toMatch(/Downloads/i)
    expect(linuxPathFocus('/home/tester/.config/autostart/x.desktop')).toMatch(/autostart/i)
    expect(linuxPathFocus('/home/tester/.local/bin/tool')).toMatch(/PATH/i)
  })

  it('explains ClamAV absence clearly', () => {
    const note = linuxEnvironmentNote({ step: 'defender', clamAvailable: false })
    expect(note).toMatch(/not installed/i)
    expect(note).toMatch(/clamav/i)
  })

  it('returns full engines line on init without detail', () => {
    const note = linuxEnvironmentNote({ step: 'init' })
    expect(note).toMatch(/YARA/i)
    expect(note).toMatch(/ClamAV/i)
    expect(note).toMatch(/heuristics|persistence/i)
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
