<!--
Copyright 2026 Visa, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
# Third-Party License Inventory

vvaharness is licensed under Apache-2.0 (see `LICENSE`). It depends on the
third-party packages listed below. These dependencies are installed from PyPI
at install time (`pipx install .` / `pip install .`) and are **not** vendored
or redistributed as part of this repository. This inventory is provided for
transparency and compliance review.

**Source:** = SPDX exports of this scan
is dated 2026-08-03. The table below lists
the project's direct runtime dependencies with the version constraints
declared in `pyproject.toml` and the licenses reported by the scan. Transitive
packages are resolved and installed from PyPI at install time (not vendored);
the SBOM is the system of record for the full transitive closure.

### Direct runtime dependencies

| Package | Version | License |
|---|---|---|
| pydantic | >=2.13.4 | MIT |
| pydantic-settings | >=2.14.1 | MIT |
| PyYAML | >=6.0.3 | MIT |
| anthropic | >=0.107.0 | MIT |
| openai | >=2.41.0 | Apache-2.0 |
| httpx | >=0.28.1 | BSD-3-Clause |
| urllib3 | >=2.7.0 | MIT |
| python-dotenv | >=1.2.2 | BSD-3-Clause |
| typing_extensions | >=4.0 | PSF-2.0 |
| claude-agent-sdk | >=0.2.87 | MIT |
| deepagents | >=0.6.8,<0.7 | MIT |
| langchain | >=0.3.0 | MIT |
| langchain-anthropic | >=0.3.0 | MIT |
| langchain-openai | >=0.3.0 | MIT |
| langgraph | >=0.3.0 | MIT |
| tree-sitter | >=0.26.0,<0.27 | MIT |
| tree-sitter-language-pack | >=1.14.0,<2 | MIT |

Transitive dependencies pulled in from PyPI (e.g. `anyio`, `annotated-types`,
`h11`, `httpcore`, `idna`, `sniffio`, `distro`, `jiter`, `pydantic-core`,
`packaging`) are permissive — MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause,
CNRI-Python, MIT-0, or PSF-2.0 — except `certifi` and `tqdm`, which are
MPL-2.0 (weak-copyleft at the file level). The SBOM closure contains **no**
reciprocal or strong-copyleft licenses (no GPL / LGPL / AGPL / EPL), so nothing
imposes copyleft obligations on first-party source and all are compatible with
an Apache-2.0 outbound license.