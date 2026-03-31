# Security Analysis Report

Generated: 2026-03-30T21:42:11
Transcript files: 251
Sessions: 251
Projects: 25
Date range: None to 2026-03-30

## Scores

- Overall: 14
- Secrets: 0
- Remote access: 0
- Permissions: 39
- Commands: 0
- Agent oversight: 43

## Secrets

- Total matches: 622
- Sensitive reads: 82
- .env writes: 34
- Unique .env paths: 14

| Type | Count |
|---|---:|
| secret_assignments | 169 |
| key_assignments | 155 |
| postgres_urls | 103 |
| bearer_tokens | 97 |
| anthropic_tokens | 96 |
| mysql_urls | 2 |

## Remote Access

- SSH commands: 882
- Production hits: 321
- Unique hosts: 21
- Active days: 13

| Host | Count |
|---|---:|
| veridas-staging | 392 |
| bitnami@52.208.186.140 | 106 |
| vibenalytics | 84 |
| genboard.sk | 78 |
| cloud@orb | 44 |
| vibenalytics@orb | 37 |
| webgate.codes | 33 |
| bitnami@108.131.254.148 | 28 |
| webgate.tech | 27 |
| unknown | 16 |
| api.webgate.tech | 13 |
| hetzner-openclaw | 12 |
| -vT | 3 |
| vibenalytics.orb.local | 2 |
| default@vibenalytics.orb.local | 1 |
| martinvanco@vibenalytics.orb.local | 1 |
| veridas-prod | 1 |
| openclaw@91.98.68.118 | 1 |
| root@91.98.68.118 | 1 |
| -t | 1 |
| 2 | 1 |

## Risky Commands

- Total flagged Bash commands: 1033

| Severity | Count |
|---|---:|
| critical | 4 |
| high | 351 |
| medium | 328 |
| low | 350 |

| Category | Count |
|---|---:|
| npx execution | 350 |
| sudo | 301 |
| write redirect | 160 |
| curl post | 159 |
| push to main | 31 |
| rm -rf | 19 |
| docker rm | 9 |
| delete without where | 3 |
| pipe to shell | 1 |

## Permissions

- Prompt total: 4413
- Bypass rate: 42.6%

| Mode | Count |
|---|---:|
| bypassPermissions | 1880 |
| acceptEdits | 1624 |
| default | 884 |
| unknown | 19 |
| plan | 6 |

## Agents

- Total agents: 470
- Agents in bypass mode: 321 (68.3%)

## Human Overrides

- Denials: 1110
- Interrupts: 0
- Override rate: 25.15%

| Tool | Denials |
|---|---:|
| Bash | 591 |
| Read | 167 |
| Edit | 100 |
| WebFetch | 69 |
| Agent | 30 |
| Write | 20 |
| mcp__google-workspace__search_gmail_messages | 19 |
| Grep | 16 |
| ExitPlanMode | 14 |
| Glob | 14 |
| mcp__google-workspace__search_drive_files | 10 |
| mcp__google-workspace__create_spreadsheet | 10 |
| mcp__google-workspace__get_doc_as_markdown | 9 |
| TaskOutput | 6 |
| mcp__google-workspace__draft_gmail_message | 5 |
| AskUserQuestion | 4 |
| mcp__google-workspace__get_doc_content | 4 |
| mcp__google-workspace__read_sheet_values | 4 |
| mcp__claude_ai_Gmail__gmail_create_draft | 3 |
| mcp__google-workspace__import_to_google_doc | 3 |
| mcp__claude_ai_Notion__notion-create-pages | 2 |
| mcp__google-workspace__start_google_auth | 2 |
| ReadMcpResourceTool | 2 |
| mcp__claude_ai_Notion__notion-search | 1 |
| WebSearch | 1 |
| mcp__google-workspace__get_gmail_thread_content | 1 |
| mcp__claude_ai_Gmail__gmail_read_message | 1 |
| mcp__google-workspace__insert_doc_image | 1 |
| mcp__google-workspace__get_spreadsheet_info | 1 |

## Stability

- Context compactions: 48
- API errors: 427

## Notes

- Secret detection is regex-based and intentionally broad.
- Risk scoring is heuristic and calibrated to match the metric families in the existing HTML reports.
- Permission mode attached to a tool call is inferred from the latest prior human prompt in the session.
