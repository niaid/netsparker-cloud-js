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
 * The Kenna integration info
 * @export
 * @interface KennaIntegrationInfoModel
 */
export interface KennaIntegrationInfoModel {
    /**
     * The API key for API requests.
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    apiKey: string;
    /**
     * The API URL.
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    apiUrl: string;
    /**
     * The days when issue is due from the time that issue is created on.
     * @type {number}
     * @memberof KennaIntegrationInfoModel
     */
    dueDays: number;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    tags?: string;
    /**
     * Set Asset application identifier
     * @type {boolean}
     * @memberof KennaIntegrationInfoModel
     */
    setAssetApplicationIdentifier?: boolean;
    /**
     * Asset application identifier type
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    assetApplicationIdentifierType?: KennaIntegrationInfoModelAssetApplicationIdentifierTypeEnum;
    /**
     * The Instance URL.
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    instanceUrl: string;
    /**
     * Asset application identifier
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    assetApplicationIdentifier?: string;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly type?: KennaIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof KennaIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof KennaIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    templateType?: KennaIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof KennaIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof KennaIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}


/**
 * @export
 */
export const KennaIntegrationInfoModelAssetApplicationIdentifierTypeEnum = {
    WebsiteName: 'WebsiteName',
    Static: 'Static'
} as const;
export type KennaIntegrationInfoModelAssetApplicationIdentifierTypeEnum = typeof KennaIntegrationInfoModelAssetApplicationIdentifierTypeEnum[keyof typeof KennaIntegrationInfoModelAssetApplicationIdentifierTypeEnum];

/**
 * @export
 */
export const KennaIntegrationInfoModelTypeEnum = {
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
export type KennaIntegrationInfoModelTypeEnum = typeof KennaIntegrationInfoModelTypeEnum[keyof typeof KennaIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const KennaIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type KennaIntegrationInfoModelTemplateTypeEnum = typeof KennaIntegrationInfoModelTemplateTypeEnum[keyof typeof KennaIntegrationInfoModelTemplateTypeEnum];


/**
 * Check if a given object implements the KennaIntegrationInfoModel interface.
 */
export function instanceOfKennaIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "apiKey" in value;
    isInstance = isInstance && "apiUrl" in value;
    isInstance = isInstance && "dueDays" in value;
    isInstance = isInstance && "instanceUrl" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function KennaIntegrationInfoModelFromJSON(json: any): KennaIntegrationInfoModel {
    return KennaIntegrationInfoModelFromJSONTyped(json, false);
}

export function KennaIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): KennaIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'apiKey': json['ApiKey'],
        'apiUrl': json['ApiUrl'],
        'dueDays': json['DueDays'],
        'tags': !exists(json, 'Tags') ? undefined : json['Tags'],
        'setAssetApplicationIdentifier': !exists(json, 'SetAssetApplicationIdentifier') ? undefined : json['SetAssetApplicationIdentifier'],
        'assetApplicationIdentifierType': !exists(json, 'AssetApplicationIdentifierType') ? undefined : json['AssetApplicationIdentifierType'],
        'instanceUrl': json['InstanceUrl'],
        'assetApplicationIdentifier': !exists(json, 'AssetApplicationIdentifier') ? undefined : json['AssetApplicationIdentifier'],
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

export function KennaIntegrationInfoModelToJSON(value?: KennaIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'ApiKey': value.apiKey,
        'ApiUrl': value.apiUrl,
        'DueDays': value.dueDays,
        'Tags': value.tags,
        'SetAssetApplicationIdentifier': value.setAssetApplicationIdentifier,
        'AssetApplicationIdentifierType': value.assetApplicationIdentifierType,
        'InstanceUrl': value.instanceUrl,
        'AssetApplicationIdentifier': value.assetApplicationIdentifier,
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

