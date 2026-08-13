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

"""Domain enums for vvaharness.validation.

Convention: value-enums subclass ``enum.StrEnum`` so ``Member == "value"``
holds; reserve a bare ``Enum`` only for a discriminator never compared to a string. All
value-enums here are ``StrEnum``.
"""

from __future__ import annotations

# EffortLevel/SettingSource are agent-backend vocabularies; they live in the shared
# harness contract and are re-exported here so validation config code keeps a single
# import site for its enum vocabulary.
from vvaharness.backends.harness.contract.effort import EffortLevel
from vvaharness.backends.harness.contract.setting_source import SettingSource

from .gates import GateName, GateStatus
from .paths import ValidationPath
from .readiness import MergeReadiness
from .verdicts import Answer, FixVerdict

__all__ = [
    "Answer",
    "EffortLevel",
    "FixVerdict",
    "GateName",
    "GateStatus",
    "MergeReadiness",
    "SettingSource",
    "ValidationPath",
]
