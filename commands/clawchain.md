---
description: Audit a dev environment's supply-chain attack surface — pip packages, VS Code extensions, and MCP servers
allowed-tools: Bash, Grep, Glob, Read, WebFetch
---

Run the `clawchain` skill to audit this project and the developer's local environment for supply-chain risk across the three entry points Darshan Yadav called out: pip packages, VS Code extensions, and MCP servers. Output a CRITICAL / HIGH / MEDIUM / LOW finding list with concrete remediation for each.

If `$ARGUMENTS` provides a path, scope the project audit to that directory. Otherwise audit the current working directory plus the user's global VS Code and MCP configs.

$ARGUMENTS
