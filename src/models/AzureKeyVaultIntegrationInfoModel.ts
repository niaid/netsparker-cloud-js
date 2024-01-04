/* tslint:disable */
/* eslint-disable */
/**
 * Invicti Enterprise API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { exists, mapValues } from '../runtime';
import type { IntegrationCustomFieldVm } from './IntegrationCustomFieldVm';
import {
    IntegrationCustomFieldVmFromJSON,
    IntegrationCustomFieldVmFromJSONTyped,
    IntegrationCustomFieldVmToJSON,
} from './IntegrationCustomFieldVm';
import type { IntegrationWizardResultModel } from './IntegrationWizardResultModel';
import {
    IntegrationWizardResultModelFromJSON,
    IntegrationWizardResultModelFromJSONTyped,
    IntegrationWizardResultModelToJSON,
} from './IntegrationWizardResultModel';

/**
 * The Vault integration info
 * @export
 * @interface AzureKeyVaultIntegrationInfoModel
 */
export interface AzureKeyVaultIntegrationInfoModel {
    /**
     * ClientId for authentication.
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    clientID: string;
    /**
     * Secret for authentication.
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    secret: string;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    agentMode?: AzureKeyVaultIntegrationInfoModelAgentModeEnum;
    /**
     * The Vault instance tenantId.
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    tenantId: string;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly type?: AzureKeyVaultIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    templateType?: AzureKeyVaultIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof AzureKeyVaultIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}


/**
 * @export
 */
export const AzureKeyVaultIntegrationInfoModelAgentModeEnum = {
    Cloud: 'Cloud',
    Internal: 'Internal'
} as const;
export type AzureKeyVaultIntegrationInfoModelAgentModeEnum = typeof AzureKeyVaultIntegrationInfoModelAgentModeEnum[keyof typeof AzureKeyVaultIntegrationInfoModelAgentModeEnum];

/**
 * @export
 */
export const AzureKeyVaultIntegrationInfoModelTypeEnum = {
    Jira: 'Jira',
    GitHub: 'GitHub',
    Tfs: 'TFS',
    FogBugz: 'FogBugz',
    ServiceNow: 'ServiceNow',
    Slack: 'Slack',
    GitLab: 'GitLab',
    Bitbucket: 'Bitbucket',
    Unfuddle: 'Unfuddle',
    Zapier: 'Zapier',
    AzureDevOps: 'AzureDevOps',
    Redmine: 'Redmine',
    Bugzilla: 'Bugzilla',
    Kafka: 'Kafka',
    PagerDuty: 'PagerDuty',
    MicrosoftTeams: 'MicrosoftTeams',
    Clubhouse: 'Clubhouse',
    Trello: 'Trello',
    Asana: 'Asana',
    Webhook: 'Webhook',
    Kenna: 'Kenna',
    Freshservice: 'Freshservice',
    YouTrack: 'YouTrack',
    NetsparkerEnterprise: 'NetsparkerEnterprise',
    Splunk: 'Splunk',
    Mattermost: 'Mattermost',
    Hashicorp: 'Hashicorp',
    PivotalTracker: 'PivotalTracker',
    CyberArk: 'CyberArk',
    DefectDojo: 'DefectDojo',
    JazzTeam: 'JazzTeam',
    AzureKeyVault: 'AzureKeyVault',
    ServiceNowVrm: 'ServiceNowVRM'
} as const;
export type AzureKeyVaultIntegrationInfoModelTypeEnum = typeof AzureKeyVaultIntegrationInfoModelTypeEnum[keyof typeof AzureKeyVaultIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const AzureKeyVaultIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type AzureKeyVaultIntegrationInfoModelTemplateTypeEnum = typeof AzureKeyVaultIntegrationInfoModelTemplateTypeEnum[keyof typeof AzureKeyVaultIntegrationInfoModelTemplateTypeEnum];


/**
 * Check if a given object implements the AzureKeyVaultIntegrationInfoModel interface.
 */
export function instanceOfAzureKeyVaultIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "clientID" in value;
    isInstance = isInstance && "secret" in value;
    isInstance = isInstance && "tenantId" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function AzureKeyVaultIntegrationInfoModelFromJSON(json: any): AzureKeyVaultIntegrationInfoModel {
    return AzureKeyVaultIntegrationInfoModelFromJSONTyped(json, false);
}

export function AzureKeyVaultIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AzureKeyVaultIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'clientID': json['ClientID'],
        'secret': json['Secret'],
        'agentMode': !exists(json, 'AgentMode') ? undefined : json['AgentMode'],
        'tenantId': json['TenantId'],
        'type': !exists(json, 'Type') ? undefined : json['Type'],
        'genericErrorMessage': !exists(json, 'GenericErrorMessage') ? undefined : json['GenericErrorMessage'],
        'identifier': !exists(json, 'Identifier') ? undefined : json['Identifier'],
        'testMessageBody': !exists(json, 'TestMessageBody') ? undefined : json['TestMessageBody'],
        'testMessageTitle': !exists(json, 'TestMessageTitle') ? undefined : json['TestMessageTitle'],
        'webhookUrl': !exists(json, 'WebhookUrl') ? undefined : json['WebhookUrl'],
        'name': !exists(json, 'Name') ? undefined : json['Name'],
        'integrationVersion': !exists(json, 'IntegrationVersion') ? undefined : json['IntegrationVersion'],
        'accountID': !exists(json, 'AccountID') ? undefined : json['AccountID'],
        'customFields': !exists(json, 'CustomFields') ? undefined : ((json['CustomFields'] as Array<any>).map(IntegrationCustomFieldVmFromJSON)),
        'templateType': !exists(json, 'TemplateType') ? undefined : json['TemplateType'],
        'reopenStatus': !exists(json, 'ReopenStatus') ? undefined : json['ReopenStatus'],
        'resolvedStatus': !exists(json, 'ResolvedStatus') ? undefined : json['ResolvedStatus'],
        'titleFormat': json['TitleFormat'],
        'integrationWizardResultModel': !exists(json, 'IntegrationWizardResultModel') ? undefined : IntegrationWizardResultModelFromJSON(json['IntegrationWizardResultModel']),
    };
}

export function AzureKeyVaultIntegrationInfoModelToJSON(value?: AzureKeyVaultIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'ClientID': value.clientID,
        'Secret': value.secret,
        'AgentMode': value.agentMode,
        'TenantId': value.tenantId,
        'Name': value.name,
        'IntegrationVersion': value.integrationVersion,
        'AccountID': value.accountID,
        'CustomFields': value.customFields === undefined ? undefined : ((value.customFields as Array<any>).map(IntegrationCustomFieldVmToJSON)),
        'TemplateType': value.templateType,
        'ReopenStatus': value.reopenStatus,
        'ResolvedStatus': value.resolvedStatus,
        'TitleFormat': value.titleFormat,
        'IntegrationWizardResultModel': IntegrationWizardResultModelToJSON(value.integrationWizardResultModel),
    };
}

