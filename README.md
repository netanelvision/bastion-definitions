# Bastion threat definitions

Nightly, signed malware definitions for the [Bastion](https://github.com/netanelvision) macOS antivirus.

Every night GitHub Actions (`.github/workflows/build.yml`):

1. downloads macOS malware hashes from [MalwareBazaar](https://bazaar.abuse.ch) (abuse.ch),
2. downloads the [YARA Forge](https://github.com/YARAHQ/yara-forge) core package and keeps the macOS rules
   from permissively licensed sources,
3. drops any rule that fails to compile or matches a clean Apple app or tool,
4. signs `manifest.json` with Bastion's Ed25519 key and publishes everything to the
   [`definitions` release](../../releases/tag/definitions).

Bastion only installs a bundle whose manifest is signed by its key and whose files match the
SHA-256 hashes in that manifest.

## Secrets

| Secret | What |
|---|---|
| `ABUSECH_KEY` | abuse.ch Auth-Key (https://auth.abuse.ch) |
| `BASTION_SIGNING_KEY` | Ed25519 private key, PEM (`~/.bastion/definitions-signing.pem` on the maintainer's Mac) |

## Run locally

```sh
brew install yara
python3 build.py && ./sign.sh   # output in dist/
```

Sources and licenses of the rules are listed in `NOTICE.txt` inside each release.
