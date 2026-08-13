<!--
Copyright 2026 Visa, Inc.
Modifications Copyright 2026 Lily Feng.
Modified by Lily Feng in 2026 for independent project governance.

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

# Contributing

Thank you for contributing to Codex Vulnerability Agentic Harness. This is an
independently maintained derivative of Visa Vulnerability Agentic Harness and
is not affiliated with or endorsed by Visa Inc. or OpenAI.

## Ways to contribute

- Report reproducible bugs through GitHub Issues.
- Propose focused improvements through pull requests.
- Improve tests, documentation, platform support, and security guidance.
- Discuss substantial design changes in an issue before investing in a large
  implementation.

## Development workflow

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

Keep changes focused, add or update tests, and do not commit credentials,
private scan targets, generated findings, or proprietary rule packs.

## Licensing contributions

Unless you explicitly state otherwise, contributions intentionally submitted
to this repository are provided under the Apache License, Version 2.0, in line
with section 5 of that license. You represent that you have the right to submit
the contribution. Preserve applicable upstream copyright and attribution
notices, and add a prominent modification notice when changing derived files.

## Security issues

Do not disclose vulnerabilities in public issues. Follow
[`SECURITY.md`](SECURITY.md) for private reporting instructions.
