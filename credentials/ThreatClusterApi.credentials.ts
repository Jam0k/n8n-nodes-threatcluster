import type {
	IAuthenticateGeneric,
	Icon,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class ThreatClusterApi implements ICredentialType {
	name = 'threatClusterApi';

	displayName = 'ThreatCluster API';

	icon: Icon = { light: 'file:threatcluster.svg', dark: 'file:threatcluster.dark.svg' };

	// eslint-disable-next-line n8n-nodes-base/cred-class-field-documentation-url-miscased
	documentationUrl = 'https://threatcluster.io/about/api-reference';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			required: true,
			description:
				'Create one under Settings → API & Feeds at threatcluster.io. Every plan, including Free, gets a read-only key.',
		},
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: 'https://threatcluster.io/api/public/v1',
			description: 'Only change this if you were given a different endpoint',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: { 'X-API-Key': '={{$credentials.apiKey}}' },
		},
	};

	// GET /me costs zero credits, so testing a credential never spends the
	// user's daily budget. It also returns the tier and scopes, which is
	// exactly what a "is this key set up right?" check should confirm.
	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl}}',
			url: '/me',
		},
	};
}
