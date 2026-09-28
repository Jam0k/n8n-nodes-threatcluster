import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	IHttpRequestOptions,
	JsonObject,
} from 'n8n-workflow';
import { NodeApiError, NodeConnectionType, NodeOperationError } from 'n8n-workflow';

/**
 * ThreatCluster action node.
 *
 * Resources mirror the API's own tags (threats / vulnerabilities / dark web /
 * entities / AI) so anyone who has read the docs can find the operation they
 * want. Everything here is a GET except Ask AI; there is no destructive
 * operation to guard.
 */
export class ThreatCluster implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'ThreatCluster',
		name: 'threatCluster',
		icon: 'file:threatcluster.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description: 'Threat intelligence: incidents, CVEs, IOCs and ransomware leak-site activity',
		defaults: { name: 'ThreatCluster' },
		// NodeConnectionType.Main, not the string: n8n-workflow 1.82 types inputs as the enum and tsc rejects 'main'.
		// eslint-disable-next-line n8n-nodes-base/node-class-description-inputs-wrong-regular-node
		inputs: [NodeConnectionType.Main],
		// eslint-disable-next-line n8n-nodes-base/node-class-description-outputs-wrong
		outputs: [NodeConnectionType.Main],
		credentials: [{ name: 'threatClusterApi', required: true }],
		properties: [
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				default: 'threat',
				// Deliberate order (most used first), not alphabetical.
				// eslint-disable-next-line n8n-nodes-base/node-param-options-type-unsorted-items
				options: [
					{ name: 'Threat Incident', value: 'threat' },
					{ name: 'Vulnerability', value: 'vulnerability' },
					{ name: 'Dark Web', value: 'darkweb' },
					{ name: 'Entity', value: 'entity' },
					{ name: 'IOC', value: 'ioc' },
					{ name: 'Ask AI', value: 'ai' },
					{ name: 'Account', value: 'account' },
				],
			},

			// ---------------------------------------------------------- threat
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['threat'] } },
				default: 'getMany',
				// Deliberate order (most used first), not alphabetical.
				// eslint-disable-next-line n8n-nodes-base/node-param-options-type-unsorted-items
				options: [
					{ name: 'Get Many', value: 'getMany', description: 'List recent incidents', action: 'List threat incidents' },
					{ name: 'Get', value: 'get', description: 'One incident by ID', action: 'Get a threat incident' },
					{ name: 'Get IOCs', value: 'getIocs', description: 'Indicators for one incident', action: 'Get IOCs for an incident' }, // eslint-disable-line n8n-nodes-base/node-param-operation-option-action-miscased
					{ name: 'Get STIX', value: 'getStix', description: 'STIX 2.1 bundle for one incident', action: 'Get a STIX bundle' },
					{ name: 'Search', value: 'search', description: 'Search incidents, entities and leak-site data', action: 'Search the corpus' },
				],
			},
			{
				displayName: 'Cluster ID',
				name: 'clusterId',
				type: 'string',
				required: true,
				default: '',
				placeholder: '971184ec',
				displayOptions: { show: { resource: ['threat'], operation: ['get', 'getIocs', 'getStix'] } },
				description: 'The short cluster ID returned by Get Many',
			},
			{
				displayName: 'Query',
				name: 'query',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'lockbit',
				displayOptions: { show: { resource: ['threat'], operation: ['search'] } },
			},
			{
				displayName: 'Time Filter',
				name: 'timeFilter',
				type: 'options',
				default: '24h',
				options: [
					{ name: 'Last Hour', value: '1h' },
					{ name: 'Last 24 Hours', value: '24h' },
					{ name: 'Last 7 Days', value: '7d' },
					{ name: 'Last 30 Days', value: '30d' },
				],
				displayOptions: { show: { resource: ['threat'], operation: ['getMany'] } },
			},
			{
				displayName: 'Sort By',
				name: 'sortBy',
				type: 'options',
				default: 'trending',
				options: [
					{ name: 'Trending', value: 'trending' },
					{ name: 'Newest', value: 'new' },
				],
				displayOptions: { show: { resource: ['threat'], operation: ['getMany'] } },
			},
			{
				displayName: 'Keyword',
				name: 'keyword',
				type: 'string',
				default: '',
				displayOptions: { show: { resource: ['threat'], operation: ['getMany'] } },
				description: 'Optional keyword filter',
			},

			// -------------------------------------------------- vulnerability
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['vulnerability'] } },
				default: 'getMany',
				options: [
					{ name: 'Get Many', value: 'getMany', description: 'List CVEs with exploitation signals', action: 'List vulnerabilities' },
					{ name: 'Get', value: 'get', description: 'One CVE by ID', action: 'Get a vulnerability' },
				],
			},
			{
				displayName: 'CVE ID',
				name: 'cveId',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'CVE-2026-1731',
				displayOptions: { show: { resource: ['vulnerability'], operation: ['get'] } },
			},
			{
				displayName: 'KEV Only',
				name: 'kevOnly',
				type: 'boolean',
				default: false,
				displayOptions: { show: { resource: ['vulnerability'], operation: ['getMany'] } },
				description: 'Whether to return only CVEs in the CISA Known Exploited Vulnerabilities catalogue',
			},
			{
				displayName: 'Has Public Exploit',
				name: 'hasExploit',
				type: 'boolean',
				default: false,
				displayOptions: { show: { resource: ['vulnerability'], operation: ['getMany'] } },
				description: 'Whether to return only CVEs with a known public exploit',
			},
			{
				displayName: 'Severity',
				name: 'severity',
				type: 'multiOptions',
				default: [],
				options: [
					{ name: 'Critical', value: 'CRITICAL' },
					{ name: 'High', value: 'HIGH' },
					{ name: 'Medium', value: 'MEDIUM' },
					{ name: 'Low', value: 'LOW' },
				],
				displayOptions: { show: { resource: ['vulnerability'], operation: ['getMany'] } },
			},

			// ------------------------------------------------------- dark web
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['darkweb'] } },
				default: 'getVictims',
				options: [
					{ name: 'Get Victims', value: 'getVictims', description: 'Ransomware leak-site listings', action: 'List leak site victims' },
					{ name: 'Get Groups', value: 'getGroups', description: 'Tracked ransomware groups', action: 'List ransomware groups' },
				],
			},
			{
				displayName: 'Group',
				name: 'group',
				type: 'string',
				default: '',
				placeholder: 'qilin',
				displayOptions: { show: { resource: ['darkweb'], operation: ['getVictims'] } },
			},
			{
				displayName: 'Sector',
				name: 'sector',
				type: 'string',
				default: '',
				placeholder: 'Healthcare',
				displayOptions: { show: { resource: ['darkweb'], operation: ['getVictims'] } },
			},
			{
				displayName: 'Country',
				name: 'country',
				type: 'string',
				default: '',
				placeholder: 'GB',
				displayOptions: { show: { resource: ['darkweb'], operation: ['getVictims'] } },
				description: 'ISO-2 country code',
			},
			{
				displayName: 'Days',
				name: 'days',
				type: 'number',
				default: 7,
				typeOptions: { minValue: 1, maxValue: 90 },
				displayOptions: { show: { resource: ['darkweb'], operation: ['getVictims'] } },
			},

			// --------------------------------------------------------- entity
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['entity'] } },
				default: 'search',
				options: [
					{ name: 'Search', value: 'search', description: 'Find actors, malware, vendors and products', action: 'Search entities' },
					{ name: 'Get', value: 'get', description: 'One entity profile', action: 'Get an entity' },
				],
			},
			{
				displayName: 'Entity Type',
				name: 'entityType',
				type: 'options',
				default: 'apt-group',
				// Deliberate order (most used first), not alphabetical.
				// eslint-disable-next-line n8n-nodes-base/node-param-options-type-unsorted-items
				options: [
					{ name: 'APT Group', value: 'apt-group' },
					{ name: 'Ransomware Group', value: 'ransomware-group' },
					{ name: 'Malware', value: 'malware' },
					{ name: 'Company', value: 'company' },
					{ name: 'Platform', value: 'platform' },
					{ name: 'CVE', value: 'cve' },
				],
				displayOptions: { show: { resource: ['entity'], operation: ['get'] } },
			},
			{
				displayName: 'Entity Value',
				name: 'entityValue',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'Qilin',
				displayOptions: { show: { resource: ['entity'], operation: ['get'] } },
			},
			{
				displayName: 'Query',
				name: 'query',
				type: 'string',
				required: true,
				default: '',
				displayOptions: { show: { resource: ['entity'], operation: ['search'] } },
			},

			// ------------------------------------------------------------ ioc
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['ioc'] } },
				default: 'getFeed',
				options: [
					{ name: 'Get Feed', value: 'getFeed', description: 'Rolling validated indicator feed', action: 'Get the IOC feed' },
				],
			},
			{
				displayName: 'Types',
				name: 'iocTypes',
				type: 'options',
				default: 'all',
				options: [
					{ name: 'All', value: 'all' },
					{ name: 'IP Addresses', value: 'ip' },
					{ name: 'Domains', value: 'domain' },
					{ name: 'Hashes', value: 'hash' },
				],
				displayOptions: { show: { resource: ['ioc'] } },
			},
			{
				displayName: 'Hours',
				name: 'hours',
				type: 'number',
				default: 24,
				typeOptions: { minValue: 1, maxValue: 720 },
				displayOptions: { show: { resource: ['ioc'] } },
			},

			// ------------------------------------------------------------- ai
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['ai'] } },
				default: 'askCorpus',
				options: [
					{ name: 'Ask the Corpus', value: 'askCorpus', description: 'Cited answer across everything (50 credits)', action: 'Ask the corpus' },
					{ name: 'Ask About an Incident', value: 'askThreat', description: 'Cited answer about one incident (25 credits)', action: 'Ask about an incident' },
				],
			},
			{
				displayName: 'Question',
				name: 'question',
				type: 'string',
				required: true,
				default: '',
				typeOptions: { rows: 2 },
				displayOptions: { show: { resource: ['ai'] } },
			},
			{
				displayName: 'Cluster ID',
				name: 'clusterId',
				type: 'string',
				required: true,
				default: '',
				displayOptions: { show: { resource: ['ai'], operation: ['askThreat'] } },
			},

			// -------------------------------------------------------- account
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: { show: { resource: ['account'] } },
				default: 'getCredits',
				options: [
					{ name: 'Get Credits', value: 'getCredits', description: 'Credits remaining today (free to call)', action: 'Get remaining credits' },
				],
			},

			// -------------------------------------------------------- shared
			{
				displayName: 'Limit',
				name: 'limit',
				type: 'number',
				default: 50,
				typeOptions: { minValue: 1 },
				displayOptions: { show: { operation: ['getMany', 'getVictims', 'search'] } },
				description: 'Max number of results to return',
			},
			{
				displayName: 'Since',
				name: 'since',
				type: 'dateTime',
				default: '',
				displayOptions: { show: { resource: ['threat', 'darkweb'], operation: ['getMany', 'getVictims'] } },
				description:
					'Only return items newer than this. Leave empty for the whole window.',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const out: INodeExecutionData[] = [];
		const credentials = await this.getCredentials('threatClusterApi');
		const baseUrl = (credentials.baseUrl as string) || 'https://threatcluster.io/api/public/v1';

		for (let i = 0; i < items.length; i++) {
			const resource = this.getNodeParameter('resource', i) as string;
			const operation = this.getNodeParameter('operation', i) as string;

			let endpoint = '';
			let method: 'GET' | 'POST' = 'GET';
			const qs: Record<string, string | number | boolean> = {};
			let body: Record<string, unknown> | undefined;

			const optional = (name: string): string => {
				const v = this.getNodeParameter(name, i, '') as string;
				return v && String(v).trim() ? String(v).trim() : '';
			};

			if (resource === 'threat') {
				if (operation === 'getMany') {
					endpoint = '/threats';
					qs.time_filter = this.getNodeParameter('timeFilter', i) as string;
					qs.sort_by = this.getNodeParameter('sortBy', i) as string;
					qs.limit = this.getNodeParameter('limit', i) as number;
					if (optional('keyword')) qs.keyword = optional('keyword');
					if (optional('since')) qs.since = optional('since');
				} else if (operation === 'search') {
					endpoint = '/search';
					qs.q = this.getNodeParameter('query', i) as string;
					qs.limit = this.getNodeParameter('limit', i) as number;
				} else {
					const id = this.getNodeParameter('clusterId', i) as string;
					endpoint =
						operation === 'getIocs' ? `/threats/${id}/iocs`
						: operation === 'getStix' ? `/threats/${id}/stix`
						: `/threats/${id}`;
				}
			} else if (resource === 'vulnerability') {
				if (operation === 'get') {
					endpoint = `/vulnerabilities/${this.getNodeParameter('cveId', i) as string}`;
				} else {
					endpoint = '/vulnerabilities';
					qs.limit = this.getNodeParameter('limit', i) as number;
					if (this.getNodeParameter('kevOnly', i) as boolean) qs.kev_only = true;
					if (this.getNodeParameter('hasExploit', i) as boolean) qs.has_exploit = true;
					const sev = this.getNodeParameter('severity', i, []) as string[];
					if (sev.length) qs.severity = sev.join(',');
				}
			} else if (resource === 'darkweb') {
				if (operation === 'getGroups') {
					endpoint = '/darkweb/ransomware/groups';
				} else {
					endpoint = '/darkweb/ransomware/victims';
					qs.days = this.getNodeParameter('days', i) as number;
					qs.limit = this.getNodeParameter('limit', i) as number;
					if (optional('group')) qs.group = optional('group');
					if (optional('sector')) qs.sector = optional('sector');
					if (optional('country')) qs.country = optional('country');
					if (optional('since')) qs.since = optional('since');
				}
			} else if (resource === 'entity') {
				if (operation === 'search') {
					endpoint = '/entities/search';
					qs.q = this.getNodeParameter('query', i) as string;
					qs.limit = this.getNodeParameter('limit', i) as number;
				} else {
					const t = this.getNodeParameter('entityType', i) as string;
					const v = encodeURIComponent(this.getNodeParameter('entityValue', i) as string);
					endpoint = `/entities/${t}/${v}`;
				}
			} else if (resource === 'ioc') {
				endpoint = '/iocs/feed';
				qs.format = 'json';
				qs.types = this.getNodeParameter('iocTypes', i) as string;
				qs.hours = this.getNodeParameter('hours', i) as number;
			} else if (resource === 'ai') {
				method = 'POST';
				const question = this.getNodeParameter('question', i) as string;
				if (operation === 'askThreat') {
					endpoint = `/threats/${this.getNodeParameter('clusterId', i) as string}/ask`;
					body = { question };
				} else {
					endpoint = '/ask';
					body = { query: question };
				}
			} else if (resource === 'account') {
				endpoint = '/me';
			}

			const options: IHttpRequestOptions = {
				method,
				url: `${baseUrl}${endpoint}`,
				qs,
				body,
				json: true,
				returnFullResponse: true,
			};

			try {
				const response = (await this.helpers.httpRequestWithAuthentication.call(
					this,
					'threatClusterApi',
					options,
				)) as { body: JsonObject; headers: Record<string, string> };

				const payload = response.body ?? {};
				const headers = response.headers ?? {};

				// Surface the budget so a workflow can see what a run cost and how
				// close it is to the daily ceiling, rather than discovering it via
				// a 429 three steps later.
				const meta = {
					creditsCost: headers['x-request-cost'],
					creditsRemaining: headers['x-ratelimit-remaining'],
					creditsResetAt: headers['x-ratelimit-reset'],
				};

				// Split list responses into one item per row: that is what every
				// downstream n8n node expects.
				const listKey = ['threats', 'victims', 'cves', 'vulnerabilities', 'iocs', 'entities', 'groups', 'results'].find(
					(k) => Array.isArray((payload as Record<string, unknown>)[k]),
				);

				if (listKey) {
					const rows = (payload as Record<string, unknown>)[listKey] as JsonObject[];
					if (rows.length === 0) {
						out.push({ json: { empty: true, resource, operation, ...meta }, pairedItem: { item: i } });
					}
					for (const row of rows) {
						out.push({ json: { ...row, _meta: meta }, pairedItem: { item: i } });
					}
				} else {
					out.push({ json: { ...payload, _meta: meta }, pairedItem: { item: i } });
				}
			} catch (error) {
				const status = (error as { httpCode?: string }).httpCode;
				// Plain-English errors: the three a user will actually hit.
				let hint = '';
				if (status === '401') hint = 'The API key was rejected. Check the credential.';
				else if (status === '403') hint =
					'Your plan does not allow this. A free key reads the last 7 days and cannot use Ask AI.';
				else if (status === '429') hint =
					'Daily credit budget spent. It refills at 00:00 UTC, or add a credit pack.';

				if (this.continueOnFail()) {
					out.push({ json: { error: hint || (error as Error).message }, pairedItem: { item: i } });
					continue;
				}
				if (hint) {
					throw new NodeOperationError(this.getNode(), hint, { itemIndex: i });
				}
				throw new NodeApiError(this.getNode(), error as JsonObject, { itemIndex: i });
			}
		}

		return [out];
	}
}
