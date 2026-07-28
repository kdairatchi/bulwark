<p align="center">
  <a href="https://github.com/kdairatchi/bulwark"><img src="logo.png" alt="Bulwark" width="128" /></a>
</p>

<h1 align="center">Bulwark</h1>

<p align="center">
  <b>A family-focused device security platform for Windows, macOS, and Linux.</b><br/>
  Protect every device in your home — without needing to be a cybersecurity expert.
</p>

<p align="center">
  <a href="https://github.com/kdairatchi/bulwark/releases"><b>Download</b></a> &nbsp;&middot;&nbsp;
  <a href="ROADMAP.md"><b>Roadmap</b></a> &nbsp;&middot;&nbsp;
  <a href="docs/product/vision.md"><b>Product Vision</b></a> &nbsp;&middot;&nbsp;
  <a href="docs/architecture/overview.md"><b>Architecture</b></a> &nbsp;&middot;&nbsp;
  <a href="CLI.md"><b>CLI Docs</b></a>
</p>

> **Naming notice.** `Bulwark` is a **temporary internal codename**, not a final brand.
> Product IDs, signing identities, and public URLs must not be locked to a final
> name until it clears the trademark/domain checks described in
> [`docs/product/vision.md`](docs/product/vision.md). This repository is a fork of
> the upstream [Kudu](https://github.com/adventdevinc/kudu) system cleaner and reuses
> its cleaning/scanning engine as the **desktop endpoint agent**.

---

## What Bulwark is

Bulwark protects the devices in a home or small business from malware, unsafe apps,
vulnerable software, malicious network traffic, and privacy risks. It is built as a
**local-first security agent** with an optional cloud control plane:

```
Desktop Agent          Android Agent           Network Sensor          Cloud Control Plane
├── Windows            ├── Phones              ├── DNS filtering       ├── Device dashboard
├── macOS              ├── Tablets             ├── Threat blocking     ├── Alerts
└── Linux              └── Android TV boxes    ├── Device discovery    ├── Vuln intelligence
                                               └── Traffic analysis    ├── Breach monitoring
                                                                       ├── Reports
                                                                       └── Remote actions
```

The desktop agent in this repository is the foundation. See
[`docs/architecture/overview.md`](docs/architecture/overview.md) for the full target
architecture and [`ROADMAP.md`](ROADMAP.md) for the phased plan.

## Desktop agent capabilities (today)

- **Malware Scanner** — YARA-X signature matching, heuristics, and Defender integration
- **Vulnerability checks** — software inventory correlated against CVE data
- **Security posture** — platform health checks (firewall, disk encryption, updates, and more)
- **Threat Monitor** — malicious-destination indicators and network telemetry
- **Breach Monitor** — email exposure checks
- **System hygiene** — cleaning, startup management, and optimization (the original engine)
- **[CLI Mode](CLI.md)** — scriptable, no GUI required

## Local-first & privacy

Bulwark runs **local-first**. Cloud features are **opt-in** and require limited,
minimum-necessary telemetry (device metadata, security findings, destination
indicators). File contents, passwords, private messages, packet payloads, and personal
documents are **never** collected. See [`docs/privacy/README.md`](docs/privacy/README.md).

## Download

Get the latest installer for your platform from
[GitHub Releases](https://github.com/kdairatchi/bulwark/releases):

| Platform | Format |
|----------|--------|
| Windows | `.exe` installer |
| macOS | `.dmg` (Intel & Apple Silicon) |
| Linux | `.AppImage` or `.deb` |

## Development

```bash
npm install     # install dependencies (rebuilds native modules)
npm run dev     # launch the desktop agent with HMR
npm test        # run the test suite (Vitest)
npm run build   # build main/preload/renderer
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md) for details.

## Documentation

- [Product vision](docs/product/vision.md)
- [Architecture](docs/architecture/overview.md)
- [Threat model](docs/threat-model/README.md)
- [Privacy architecture](docs/privacy/README.md)
- [API design](docs/api/device-and-dashboard-api.md)
- [Roadmap](ROADMAP.md)

## Disclaimer

Bulwark performs security actions and, via its cleaning engine, can remove files from
your system. You are responsible for reviewing items before removal. The software is
provided "as is" without warranty.

## Credits

Bulwark is a fork of [Kudu](https://github.com/adventdevinc/kudu) by the Kudu
Contributors, reused under the MIT license as the desktop endpoint agent.

## License

[MIT](LICENSE)
