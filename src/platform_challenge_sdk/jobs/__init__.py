"""Job submission client for challenges to submit jobs to platform-api."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class JobSubmitter:
    """Client for submitting jobs to platform-api from challenges."""

    def __init__(self, platform_api_url: str | None = None, challenge_id: str | None = None):
        """Initialize job submitter.

        Args:
            platform_api_url: Platform API base URL (defaults to PLATFORM_API_URL env var)
            challenge_id: Challenge ID (defaults to CHALLENGE_ID env var)
        """
        self.platform_api_url = platform_api_url or os.getenv("PLATFORM_API_URL", "http://localhost:3000")
        self.challenge_id = challenge_id or os.getenv("CHALLENGE_ID", "")
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def submit_evaluation_job(
        self,
        job_name: str,
        payload: dict[str, Any],
        priority: str = "normal",
        timeout: int | None = None,
        max_retries: int | None = None,
    ) -> dict[str, Any]:
        """Submit an evaluation job to platform-api.

        Args:
            job_name: Name of the job (e.g., "evaluate_agent")
            payload: Job payload containing agent_hash and other parameters
            priority: Job priority ("low", "normal", "high", "critical")
            timeout: Job timeout in seconds
            max_retries: Maximum number of retries

        Returns:
            Job metadata including job_id

        Raises:
            httpx.HTTPError: If job submission fails
        """
        if not self.challenge_id:
            raise ValueError("challenge_id must be set (via constructor or CHALLENGE_ID env var)")

        request_data = {
            "job_name": job_name,
            "payload": payload,
            "challenge_id": self.challenge_id,
            "priority": priority,
        }

        if timeout is not None:
            request_data["timeout"] = timeout
        if max_retries is not None:
            request_data["max_retries"] = max_retries

        client = self._get_client()
        url = f"{self.platform_api_url}/api/jobs/challenge/create-job"

        try:
            response = await client.post(url, json=request_data)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Failed to submit job to platform-api: {e}")
            raise

    async def get_job_status(self, job_id: str) -> dict[str, Any]:
        """Get status of a job.

        Args:
            job_id: Job ID to check

        Returns:
            Job metadata with current status

        Raises:
            httpx.HTTPError: If request fails
        """
        client = self._get_client()
        url = f"{self.platform_api_url}/api/jobs/{job_id}"

        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Failed to get job status: {e}")
            raise

    async def cancel_job(self, job_id: str) -> dict[str, Any]:
        """Cancel a job.

        Args:
            job_id: Job ID to cancel

        Returns:
            Cancellation result

        Raises:
            httpx.HTTPError: If cancellation fails
        """
        client = self._get_client()
        url = f"{self.platform_api_url}/api/jobs/{job_id}/fail"

        try:
            response = await client.post(url, json={"reason": "cancelled_by_challenge"})
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Failed to cancel job: {e}")
            raise

    async def batch_submit_jobs(
        self,
        job_requests: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Submit multiple jobs in batch.

        Args:
            job_requests: List of job request dicts, each containing:
                - job_name: Name of the job
                - payload: Job payload
                - priority: Optional priority (defaults to "normal")
                - timeout: Optional timeout
                - max_retries: Optional max retries

        Returns:
            List of job metadata dicts

        Raises:
            httpx.HTTPError: If any job submission fails
        """
        results = []
        for request in job_requests:
            try:
                result = await self.submit_evaluation_job(
                    job_name=request["job_name"],
                    payload=request["payload"],
                    priority=request.get("priority", "normal"),
                    timeout=request.get("timeout"),
                    max_retries=request.get("max_retries"),
                )
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to submit job in batch: {e}")
                results.append({"error": str(e)})
        return results

    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


