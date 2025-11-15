<div align="center">

<pre>
█▀▀ █░█ ▄▀█ █░░ █░░ █▀▀ █▄░█ █▀▀ █▀▀   █▀ █▀▄ █▄▀
█▄▄ █▀█ █▀█ █▄▄ █▄▄ ██▄ █░▀█ █▄█ ██▄   ▄█ █▄▀ █░█
</pre>


<a name="readme-top"></a>

A modern, secure, and developer-friendly Python SDK for building verifiable challenges<br/>on Platform Network using confidential computing with end-to-end security,<br/>using the technology from [Dstack-TEE](https://github.com/Dstack-TEE/dstack).

[![Python version][python_version_img]][python_url]
[![License][repo_license_img]][repo_license_url]
[![PEP 621][pep621_img]][pep621_url]

**↗️ The official Challenge SDK documentation ↗️**

[Getting Started](docs/getting-started.md) · [Architecture](docs/architecture.md) · [Usage](docs/usage.md) · [Security](docs/security.md) · [API Reference](docs/api-reference.md)

</div>

> [!CAUTION]
> Challenge SDK is currently in early development. Some features may be incomplete, APIs may change, and potential security vulnerabilities may exist. The team is actively testing to ensure everything is properly implemented and stable. Not ready for production use.

## Features

- **End-to-End Security**: Encrypted WebSocket communication with TDX attestation (X25519/ChaCha20-Poly1305), Ed25519 signed requests, and encrypted credential management.

- **Lifecycle Management**: Decorator-based handlers for startup, ready, job evaluation, and cleanup.

- **Database Migrations**: Automatic versioned migrations with sealed credential decryption.

- **Custom Weights**: Flexible weights calculation for mining allocation.

- **Public APIs**: Built-in support for custom public endpoints.

- **Monitoring**: Health checks and comprehensive logging.

<div align="right">

[↗ Back to top](#readme-top)

</div>

## Quick Start

> [!NOTE]
> Challenge SDK requires Python 3.10 or higher.

Install the Challenge SDK:

```console
pip install platform-challenge-sdk
```

Or install from source:

```console
git clone https://github.com/PlatformNetwork/challenge.git
cd challenge
pip install -e .
```

Create a new challenge file `my_challenge.py`:

```python
from platform_challenge_sdk import challenge, run, Context

@challenge.on_startup()
async def on_startup():
    print("Challenge initializing...")

@challenge.on_ready()
async def on_ready():
    print("Challenge ready to accept jobs!")

@challenge.on_job()
def evaluate(ctx: Context, payload: dict) -> dict:
    return {
        "score": 0.95,
        "metrics": {"accuracy": 0.95},
        "job_type": "inference",
    }

if __name__ == "__main__":
    run()
```

See [Getting Started](docs/getting-started.md) for detailed installation and usage instructions.

## Documentation

For complete documentation, see:

- **[Getting Started](docs/getting-started.md)** - Installation, prerequisites, and quick start guide
- **[Architecture](docs/architecture.md)** - System architecture, components, and Platform API/Validator roles
- **[Usage](docs/usage.md)** - Challenge lifecycle, job evaluation, weights, and public endpoints
- **[Security](docs/security.md)** - Security architecture, TDX attestation, and encryption details
- **[API Reference](docs/api-reference.md)** - Complete API documentation (decorators, context, endpoints)
- **[Database Migrations](docs/database-migrations.md)** - Migration guide and examples
- **[Development](docs/development.md)** - Development setup, project structure, and tools
- **[Troubleshooting](docs/troubleshooting.md)** - Common errors and solutions

## License

```
Copyright 2025 Cortex Foundation

Licensed under the MIT License.

See LICENSE file for details.
```

<div align="right">

[↗ Back to top](#readme-top)

</div>

---

<div align="center">

**[Back to top](#readme-top)**

Made with love by the Cortex Foundation

</div>

<!-- Python links -->

[python_url]: https://www.python.org/
[python_download_url]: https://www.python.org/downloads/
[python_version_img]: https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python

<!-- Repository links -->

[repo_license_url]: https://github.com/PlatformNetwork/challenge/blob/main/LICENSE
[repo_license_img]: https://img.shields.io/badge/license-MIT-blue?style=for-the-badge&logo=none

<!-- PEP 621 links -->

[pep621_url]: https://peps.python.org/pep-0621/
[pep621_img]: https://img.shields.io/badge/PEP%20621-compliant-blue?style=for-the-badge&logo=none
