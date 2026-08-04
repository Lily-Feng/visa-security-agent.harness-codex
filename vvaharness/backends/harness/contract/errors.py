# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Harness-owned exception hierarchy wrapping SDK-specific error classes."""


class HarnessError(Exception):
    """Base class for all harness-level failures."""


class HarnessCLINotFoundError(HarnessError):
    """Underlying CLI binary is missing. Fatal for the whole batch."""


class HarnessConnectionError(HarnessError):
    """Connection to the underlying agent runtime failed."""


class HarnessProcessError(HarnessError):
    """Agent process exited abnormally. Carries exit_code and stderr tail."""

    def __init__(
        self,
        message: str,
        exit_code: int | None = None,
        stderr: str | None = None,
    ) -> None:
        """Store message, exit_code, and stderr tail."""
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


class HarnessJSONDecodeError(HarnessError):
    """JSON decode failure on agent output."""


class HarnessMessageParseError(HarnessError):
    """Message parsing failed mid-stream."""
