"""Mock TDX client for testing."""
import base64
import json


class MockTdxClient:
    """Mock TDX client for testing."""

    def __init__(self, should_succeed: bool = True):
        self.should_succeed = should_succeed
        self.mock_quote = b"0" * 1024  # Minimum TDX quote size
        self.mock_event_log = {"environment_mode": "dev"}

    async def get_quote(self, report_data: bytes) -> dict:
        """Mock getting TDX quote."""
        if not self.should_succeed:
            raise ValueError("Mock TDX: Failed to get quote")

        return {
            "quote": base64.b64encode(self.mock_quote).decode("ascii"),
            "event_log": json.dumps(self.mock_event_log),
            "rtmrs": ["0" * 96] * 4,
        }

