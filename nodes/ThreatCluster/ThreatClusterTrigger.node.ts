import type {
	IPollFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	IHttpRequestOptions,
	JsonObject,
} from 'n8n-workflow';
import { NodeConnectionType, NodeOperationError } from 'n8n-workflow';

/**
 * ThreatCluster polling trigger.
 *
 * Two layers of protection against duplicate alerts, which is the classic way
 * a community poller ships broken:
 *
 *   1. `since` — the API filters server-side to items newer than the last run,
 *      so a poll costs one call and returns only what changed.
 *   2. A local ring of seen IDs — belt and braces for rows that share a
 *      timestamp, or arrive slightly out of order, or when the workflow is
 *      re-activated and `since` is briefly unset.
 *
 * Both matter. `since` alone can re-emit an item whose timestamp equals the
 * boundary; the ID set alone would force a full-window fetch every run.
 */
export class ThreatClusterTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'ThreatCluster Trigger',
		name: 'threatClusterTrigger',
		icon: 'file:threatcluster.svg',
		group: ['trigger'],
		version: 1,
		subtitle: '={{$parameter["event"]}}',
		description: 'Starts a workflow when ThreatCluster sees something new',
		defaults: { name: 'ThreatCluster Trigger' },
		polling: true,
		inputs: [],
		// eslint-disable-next-line n8n-nodes-base/node-class-description-outputs-wrong
		outputs: [NodeConnectionType.Main],
		credentials: [{ name: 'threatClusterApi', required: true }],
		properties: [
			{
				displayName: 'Event',
				name: 'event',
				type: 'options',
				noDataExpression: true,
				default: 'newIncident',
				options: [
					{ name: 'New Threat Incident', value: 'newIncident', description: 'A new incident cluster was formed' },
					{ name: 'New Leak-Site Victim', value: 'newVictim', description: 'A ransomware group listed a new organisation' },
					{ name: 'New Exploited CVE', value: 'newExploitedCve', description: 'A CVE entered KEV or gained a public exploit' },
				],
			},
			{
				displayName: 'Minimum Threat Score',
				name: 'minScore',
				type: 'number',
				default: 0,
				typeOptions: { minValue: 0, maxValue: 100 },
				displayOptions: { show: { event: ['newIncident'] } },
				description: 'Ignore incidents scoring below this. 0 emits everything.',
			},
			{
				displayName: 'Keyword',
				name: 'keyword',
				type: 'string',
				default: '',
				displayOptions: { show: { event: ['newIncident'] } },
				description: 'Only incidents matching this keyword',
			},
			{
				displayName: 'Sector',
				name: 'sector',
				type: 'string',
				default: '',
				placeholder: 'Healthcare',
				displayOptions: { show: { event: ['newVictim'] } },
				description: 'Only victims in this sector',
			},
			{
				displayName: 'Country',
				name: 'country',
				type: 'string',
				default: '',
				placeholder: 'GB',
				displayOptions: { show: { event: ['newVictim'] } },
				description: 'ISO-2 country code',
			},
		],
	};

	async poll(this: IPollFunctions): Promise<INodeExecutionData[][] | null> {
		const event = this.getNodeParameter('event') as string;
		const credentials = await this.getCredentials('threatClusterApi');
		const baseUrl = (credentials.baseUrl as string) || 'https://threatcluster.io/api/public/v1';

		const staticData = this.getWorkflowStaticData('node') as {
			lastSeenAt?: string;
			seenIds?: string[];
		};
		const seen = new Set(staticData.seenIds ?? []);
		const firstRun = staticData.lastSeenAt === undefined;

		let endpoint: string;
		const qs: Record<string, string | number | boolean> = {};
		let listKey: string;
		let idOf: (row: JsonObject) => string;
		let timeOf: (row: JsonObject) => string | undefined;

		if (event === 'newVictim') {
			endpoint = '/darkweb/ransomware/victims';
			listKey = 'victims';
			qs.days = 7;
			qs.limit = 100;
			const sector = this.getNodeParameter('sector', '') as string;
			const country = this.getNodeParameter('country', '') as string;
			if (sector) qs.sector = sector;
			if (country) qs.country = country;
			idOf = (r) => `${r.group ?? r.group_name}|${r.name ?? r.victim_name}|${r.discovered}`;
			timeOf = (r) => (r.discovered as string) ?? undefined;
		} else if (event === 'newExploitedCve') {
			endpoint = '/vulnerabilities';
			listKey = 'cves';
			qs.days = 7;
			qs.limit = 50;
			qs.has_exploit = true;
			idOf = (r) => String(r.cve_id);
			timeOf = (r) => (r.published_date as string) ?? undefined;
		} else {
			endpoint = '/threats';
			listKey = 'threats';
			qs.time_filter = '24h';
			qs.sort_by = 'new';
			qs.limit = 50;
			const keyword = this.getNodeParameter('keyword', '') as string;
			if (keyword) qs.keyword = keyword;
			idOf = (r) => String(r.cluster_id);
			timeOf = (r) => (r.date_range_latest as string) ?? (r.created_at as string) ?? undefined;
		}

		// Server-side incremental filter. Skipped on the first run so the
		// workflow has something to show when the user hits "Fetch Test Event".
		if (staticData.lastSeenAt && endpoint !== '/vulnerabilities') {
			qs.since = staticData.lastSeenAt;
		} else if (staticData.lastSeenAt) {
			qs.published_after = staticData.lastSeenAt.slice(0, 10);
		}

		const options: IHttpRequestOptions = {
			method: 'GET',
			url: `${baseUrl}${endpoint}`,
			qs,
			json: true,
		};

		let payload: JsonObject;
		try {
			payload = (await this.helpers.httpRequestWithAuthentication.call(
				this,
				'threatClusterApi',
				options,
			)) as JsonObject;
		} catch (error) {
			const status = (error as { httpCode?: string }).httpCode;
			if (status === '429') {
				// Never throw on a budget ceiling: that would disable the workflow.
				// Poll again next interval, once the budget has refilled.
				return null;
			}
			if (status === '401') {
				throw new NodeOperationError(this.getNode(), 'The API key was rejected. Check the credential.');
			}
			throw error;
		}

		const rows = (payload[listKey] as JsonObject[]) ?? [];
		const minScore = event === 'newIncident' ? (this.getNodeParameter('minScore', 0) as number) : 0;

		const fresh: JsonObject[] = [];
		let newest = staticData.lastSeenAt ?? '';

		for (const row of rows) {
			const id = idOf(row);
			const ts = timeOf(row);
			if (ts && ts > newest) newest = ts;
			if (seen.has(id)) continue;
			if (minScore && Number(row.threat_score ?? 0) < minScore) continue;
			seen.add(id);
			fresh.push(row);
		}

		// Keep the seen-set bounded; the `since` filter means we only ever need
		// enough history to cover timestamp ties around the boundary.
		staticData.seenIds = Array.from(seen).slice(-500);
		if (newest) staticData.lastSeenAt = newest;

		// On the very first poll, prime state and emit a single sample rather
		// than flooding the workflow with a whole window of history.
		if (firstRun) {
			return fresh.length ? [[{ json: fresh[0] }]] : null;
		}

		if (this.getMode() === 'manual') {
			return rows.length ? [[{ json: rows[0] }]] : null;
		}

		return fresh.length ? [fresh.map((json) => ({ json }))] : null;
	}
}
