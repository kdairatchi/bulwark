/** Shared DNS query helpers for resolver / e2e tests (no I/O beyond UDP send). */

import dgram from 'dgram'

/** Build a minimal DNS query for name/qtype. */
export function buildDnsQuery(name: string, qtype = 1, id = 0x4242): Buffer {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(id, 0)
  header.writeUInt16BE(0x0100, 2) // RD
  header.writeUInt16BE(1, 4) // QDCOUNT
  const labels = name.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]))
  const qname = Buffer.concat([...labels, Buffer.from([0])])
  const tail = Buffer.alloc(4)
  tail.writeUInt16BE(qtype, 0)
  tail.writeUInt16BE(1, 2) // class IN
  return Buffer.concat([header, qname, tail])
}

/** Send a DNS query over UDP and wait for one response. */
export function udpQueryDns(port: number, msg: Buffer, host = '127.0.0.1', timeoutMs = 2000): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4')
    const timer = setTimeout(() => { sock.close(); reject(new Error('dns udp timeout')) }, timeoutMs)
    sock.on('message', (res) => { clearTimeout(timer); sock.close(); resolve(res) })
    sock.on('error', (e) => { clearTimeout(timer); sock.close(); reject(e) })
    sock.send(msg, port, host)
  })
}

/** Last four bytes of an A-answer sinkhole (0.0.0.0). */
export function aRecordSinkhole(response: Buffer): number[] {
  return [...response.subarray(response.length - 4)]
}
