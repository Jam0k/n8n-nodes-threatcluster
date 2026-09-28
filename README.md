# n8n-nodes-threatcluster

Use [ThreatCluster](https://threatcluster.io) threat intelligence in your n8n
workflows: incident clusters, CVEs with exploitation signals, validated
indicators, and ransomware leak-site activity.

Every plan including Free gets a read-only API key, so you can build and test
this without talking to anyone.

## Installation

**n8n Cloud / self-hosted UI** — Settings → Community Nodes → Install →
`n8n-nodes-threatcluster`.

**Self-hosted, manually:**

```bash
cd ~/.n8n/nodes
npm install n8n-nodes-threatcluster
```

## Credential

Create an API key at threatcluster.io under **Settings → API & Feeds**, then add
a **ThreatCluster API** credential in n8n and paste it in. The credential test
calls `GET /me`, which costs zero credits, so testing never spends your budget.

## Nodes

### ThreatCluster (action)

| Resource | Operations |
|---|---|
| Threat Incident | Get Many, Get, Get IOCs, Get STIX, Search |
| Vulnerability | Get Many (KEV / public-exploit / severity filters), Get |
| Dark Web | Get Victims, Get Groups |
| Entity | Search, Get |
| IOC | Get Feed |
| Ask AI | Ask the Corpus, Ask About an Incident |
| Account | Get Credits |

List responses are split into one item per row, which is what downstream n8n
nodes expect. Every item carries a `_meta` object with what the call cost and
how many credits remain today.

### ThreatCluster Trigger (polling)

Three events: **New Threat Incident**, **New Leak-Site Victim**, **New Exploited
CVE**.

Deduplication is handled for you, and it matters — duplicate alerts are the
usual way a polling integration goes wrong. Two layers:

1. The API's `since` parameter filters server-side to items newer than the last
   run, so a poll costs one call and returns only what changed.
2. A local set of seen IDs catches rows that share a timestamp or arrive out of
   order.

The first poll primes state and emits a single sample rather than flooding your
workflow with a whole window of history.

## Credits

Free keys get 100 credits a day and read the last seven days; Researcher gets
1,000 and full history. Most calls cost 1 credit; search costs 5, STIX and the
IOC feed 3, Ask AI 25 to 50. `Get Credits` is free.

The node turns the three errors you will actually hit into plain English:

- **401** — the key was rejected, check the credential
- **403** — your plan does not allow it (a free key cannot use Ask AI, and reads only the last 7 days)
- **429** — the daily budget is spent; it refills at 00:00 UTC

The trigger treats a 429 as "try again next interval" rather than failing, so a
busy day never disables your workflow.

## Example workflows

**Ransomware watch for your sector** — Trigger (New Leak-Site Victim, sector
`Healthcare`) → Slack. One message per new listing.

**Exploited CVE triage** — Trigger (New Exploited CVE) → Filter (severity is
CRITICAL) → create a ticket.

**Enrich an alert** — your SIEM webhook → ThreatCluster (Entity: Get) → post the
actor profile back into the case.

## Licence

MIT. Data returned by the API is subject to the
[ThreatCluster terms](https://threatcluster.io/terms).
