# Getting Started

## Prerequisites

- Python 3.10 or higher
- Platform Network validator access
- TDX-capable hardware (for production deployments)

## Installation

### Option 1: Install from PyPI

```bash
pip install platform-challenge-sdk
```

### Option 2: Install from Source

```bash
git clone https://github.com/PlatformNetwork/challenge.git
cd challenge
pip install -e .
```

### Option 3: Install with Dev Dependencies

```bash
pip install -e ".[dev]"
pre-commit install
```

## Quick Start

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
    score = 0.95
    metrics = {"accuracy": 0.95, "latency_ms": 150}
    job_type = "inference"
    
    return {
        "score": score,
        "metrics": metrics,
        "job_type": job_type,
    }

@challenge.on_weights()
def on_weights(jobs: list[dict]) -> dict[str, float]:
    weights = {}
    for job in jobs:
        uid = str(job.get("uid"))
        score = float(job.get("score", 0.0))
        weights[uid] = max(score, 0.0)
    return weights

if __name__ == "__main__":
    run()
```

Run your challenge:

```bash
python my_challenge.py
```

## Next Steps

- Learn about the [Architecture](architecture.md) to understand how the SDK works
- Read the [Usage Guide](usage.md) for detailed examples
- Check the [API Reference](api-reference.md) for all available decorators and methods
- See [Examples](../examples/) directory for complete challenge implementations

