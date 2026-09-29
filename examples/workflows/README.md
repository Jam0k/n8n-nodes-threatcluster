# Example workflows

Five workflows that were run end to end on n8n 2.41.3 with version 0.1.2 of this node, on 29 September 2026. Screenshots of each run are at https://threatcluster.io/integrations/n8n

| File | What it does | Credits per run |
|---|---|---|
| `cve-triage.json` | Every morning, lists CVEs that are in CISA KEV and have a public exploit, keeps the criticals and creates one ticket each | 1 |
| `morning-briefing.json` | On weekdays, takes the five top trending incidents and posts one briefing message | 1 |
| `alert-enrichment.json` | Receives an alert from a SIEM by webhook, looks up its CVE and replies with a priority | 1 |
| `hash-watchlist.json` | Every four hours, pulls malware hashes from the indicator feed and sends the SHA-256 list to an EDR | 3 |
| `trigger-alert.json` | Polls for newly exploited CVEs and posts one message for each | 1 per poll |

## Importing

1. In n8n, create a workflow, open the menu at the top right and select **Import from File**.
2. Open each ThreatCluster node and pick your ThreatCluster API credential. The files carry no credentials.
3. Replace the placeholder URL in the last node with your own Slack webhook, ticketing API or EDR endpoint, or swap the node for n8n's Slack or Jira node.
