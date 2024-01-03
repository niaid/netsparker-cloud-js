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
 * 
 * @export
 * @interface CyberArkVaultIntegrationInfoModel
 */
export interface CyberArkVaultIntegrationInfoModel {
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    certificateFileKey?: string;
    /**
     * Pfx File Password for authentication.
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    certificateFilePassword?: string;
    /**
     * The Vault instance URL.
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    url: string;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    agentMode?: CyberArkVaultIntegrationInfoModelAgentModeEnum;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly type?: CyberArkVaultIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    templateType?: CyberArkVaultIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof CyberArkVaultIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}


/**
 * @export
 */
export const CyberArkVaultIntegrationInfoModelAgentModeEnum = {
    Cloud: 'Cloud',
    Internal: 'Internal'
} as const;
export type CyberArkVaultIntegrationInfoModelAgentModeEnum = typeof CyberArkVaultIntegrationInfoModelAgentModeEnum[keyof typeof CyberArkVaultIntegrationInfoModelAgentModeEnum];

/**
 * @export
 */
export const CyberArkVaultIntegrationInfoModelTypeEnum = {
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
export type CyberArkVaultIntegrationInfoModelTypeEnum = typeof CyberArkVaultIntegrationInfoModelTypeEnum[keyof typeof CyberArkVaultIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const CyberArkVaultIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type CyberArkVaultIntegrationInfoModelTemplateTypeEnum = typeof CyberArkVaultIntegrationInfoModelTemplateTypeEnum[keyof typeof CyberArkVaultIntegrationInfoModelTemplateTypeEnum];


/**
 * Check if a given object implements the CyberArkVaultIntegrationInfoModel interface.
 */
export function instanceOfCyberArkVaultIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function CyberArkVaultIntegrationInfoModelFromJSON(json: any): CyberArkVaultIntegrationInfoModel {
    return CyberArkVaultIntegrationInfoModelFromJSONTyped(json, false);
}

export function CyberArkVaultIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): CyberArkVaultIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'certificateFileKey': !exists(json, 'CertificateFileKey') ? undefined : json['CertificateFileKey'],
        'certificateFilePassword': !exists(json, 'CertificateFilePassword') ? undefined : json['CertificateFilePassword'],
        'url': json['Url'],
        'agentMode': !exists(json, 'AgentMode') ? undefined : json['AgentMode'],
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

export function CyberArkVaultIntegrationInfoModelToJSON(value?: CyberArkVaultIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'CertificateFileKey': value.certificateFileKey,
        'CertificateFilePassword': value.certificateFilePassword,
        'Url': value.url,
        'AgentMode': value.agentMode,
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
