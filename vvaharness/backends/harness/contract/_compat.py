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

"""``StrEnum`` re-export for the shared harness contract.

``enum.StrEnum`` is Python 3.11+, which the project floor now requires, so this
is a plain re-export. It previously carried a 3.10 backport; that branch became
unreachable when the floor moved to 3.11. The module is kept so the enums in
this package keep a single import site for ``StrEnum``.
"""
from __future__ import annotations

from enum import StrEnum

__all__ = ["StrEnum"]
