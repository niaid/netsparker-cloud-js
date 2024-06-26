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

import { mapValues } from '../runtime';
import type { IntegrationWizardResultModel } from './IntegrationWizardResultModel';
import {
    IntegrationWizardResultModelFromJSON,
    IntegrationWizardResultModelFromJSONTyped,
    IntegrationWizardResultModelToJSON,
} from './IntegrationWizardResultModel';
import type { IntegrationCustomFieldVm } from './IntegrationCustomFieldVm';
import {
    IntegrationCustomFieldVmFromJSON,
    IntegrationCustomFieldVmFromJSONTyped,
    IntegrationCustomFieldVmToJSON,
} from './IntegrationCustomFieldVm';

/**
 * The DefectDojo integration info
 * @export
 * @interface DefectDojoIntegrationInfoModel
 */
export interface DefectDojoIntegrationInfoModel {
    /**
     * Gets or sets the access token.
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    accessToken: string;
    /**
     * The Server URL.
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    serverUrl: string;
    /**
     * Gets or sets the labels.
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    tags?: string;
    /**
     * Gets or sets the repository.
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    engagementId: string;
    /**
     * Gets or sets the environment.
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    environment?: string;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly type?: DefectDojoIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof DefectDojoIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof DefectDojoIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    templateType?: DefectDojoIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof DefectDojoIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    id?: string;
    /**
     * 
     * @type {string}
     * @memberof DefectDojoIntegrationInfoModel
     */
    state?: DefectDojoIntegrationInfoModelStateEnum;
}


/**
 * @export
 */
export const DefectDojoIntegrationInfoModelTypeEnum = {
    NetsparkerEnterprise: 'NetsparkerEnterprise',
    Webhook: 'Webhook',
    Zapier: 'Zapier',
    Slack: 'Slack',
    Mattermost: 'Mattermost',
    MicrosoftTeams: 'MicrosoftTeams',
    AzureDevOps: 'AzureDevOps',
    Bitbucket: 'Bitbucket',
    Bugzilla: 'Bugzilla',
    Clubhouse: 'Clubhouse',
    DefectDojo: 'DefectDojo',
    PivotalTracker: 'PivotalTracker',
    Jira: 'Jira',
    FogBugz: 'FogBugz',
    GitHub: 'GitHub',
    PagerDuty: 'PagerDuty',
    Kafka: 'Kafka',
    Kenna: 'Kenna',
    Redmine: 'Redmine',
    ServiceNow: 'ServiceNow',
    Tfs: 'TFS',
    Unfuddle: 'Unfuddle',
    YouTrack: 'YouTrack',
    Freshservice: 'Freshservice',
    Splunk: 'Splunk',
    JazzTeam: 'JazzTeam',
    ServiceNowVrm: 'ServiceNowVRM',
    Asana: 'Asana',
    Trello: 'Trello',
    Hashicorp: 'Hashicorp',
    CyberArk: 'CyberArk',
    AzureKeyVault: 'AzureKeyVault',
    GitLab: 'GitLab'
} as const;
export type DefectDojoIntegrationInfoModelTypeEnum = typeof DefectDojoIntegrationInfoModelTypeEnum[keyof typeof DefectDojoIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const DefectDojoIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type DefectDojoIntegrationInfoModelTemplateTypeEnum = typeof DefectDojoIntegrationInfoModelTemplateTypeEnum[keyof typeof DefectDojoIntegrationInfoModelTemplateTypeEnum];

/**
 * @export
 */
export const DefectDojoIntegrationInfoModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
} as const;
export type DefectDojoIntegrationInfoModelStateEnum = typeof DefectDojoIntegrationInfoModelStateEnum[keyof typeof DefectDojoIntegrationInfoModelStateEnum];


/**
 * Check if a given object implements the DefectDojoIntegrationInfoModel interface.
 */
export function instanceOfDefectDojoIntegrationInfoModel(value: object): boolean {
    if (!('accessToken' in value)) return false;
    if (!('serverUrl' in value)) return false;
    if (!('engagementId' in value)) return false;
    if (!('titleFormat' in value)) return false;
    return true;
}

export function DefectDojoIntegrationInfoModelFromJSON(json: any): DefectDojoIntegrationInfoModel {
    return DefectDojoIntegrationInfoModelFromJSONTyped(json, false);
}

export function DefectDojoIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): DefectDojoIntegrationInfoModel {
    if (json == null) {
        return json;
    }
    return {
        
        'accessToken': json['AccessToken'],
        'serverUrl': json['ServerUrl'],
        'tags': json['Tags'] == null ? undefined : json['Tags'],
        'engagementId': json['EngagementId'],
        'environment': json['Environment'] == null ? undefined : json['Environment'],
        'type': json['Type'] == null ? undefined : json['Type'],
        'genericErrorMessage': json['GenericErrorMessage'] == null ? undefined : json['GenericErrorMessage'],
        'identifier': json['Identifier'] == null ? undefined : json['Identifier'],
        'testMessageBody': json['TestMessageBody'] == null ? undefined : json['TestMessageBody'],
        'testMessageTitle': json['TestMessageTitle'] == null ? undefined : json['TestMessageTitle'],
        'webhookUrl': json['WebhookUrl'] == null ? undefined : json['WebhookUrl'],
        'name': json['Name'] == null ? undefined : json['Name'],
        'integrationVersion': json['IntegrationVersion'] == null ? undefined : json['IntegrationVersion'],
        'accountID': json['AccountID'] == null ? undefined : json['AccountID'],
        'customFields': json['CustomFields'] == null ? undefined : ((json['CustomFields'] as Array<any>).map(IntegrationCustomFieldVmFromJSON)),
        'templateType': json['TemplateType'] == null ? undefined : json['TemplateType'],
        'reopenStatus': json['ReopenStatus'] == null ? undefined : json['ReopenStatus'],
        'resolvedStatus': json['ResolvedStatus'] == null ? undefined : json['ResolvedStatus'],
        'titleFormat': json['TitleFormat'],
        'integrationWizardResultModel': json['IntegrationWizardResultModel'] == null ? undefined : IntegrationWizardResultModelFromJSON(json['IntegrationWizardResultModel']),
        'id': json['Id'] == null ? undefined : json['Id'],
        'state': json['State'] == null ? undefined : json['State'],
    };
}

export function DefectDojoIntegrationInfoModelToJSON(value?: Omit<DefectDojoIntegrationInfoModel, 'Type'|'GenericErrorMessage'|'Identifier'|'TestMessageBody'|'TestMessageTitle'|'WebhookUrl'> | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'AccessToken': value['accessToken'],
        'ServerUrl': value['serverUrl'],
        'Tags': value['tags'],
        'EngagementId': value['engagementId'],
        'Environment': value['environment'],
        'Name': value['name'],
        'IntegrationVersion': value['integrationVersion'],
        'AccountID': value['accountID'],
        'CustomFields': value['customFields'] == null ? undefined : ((value['customFields'] as Array<any>).map(IntegrationCustomFieldVmToJSON)),
        'TemplateType': value['templateType'],
        'ReopenStatus': value['reopenStatus'],
        'ResolvedStatus': value['resolvedStatus'],
        'TitleFormat': value['titleFormat'],
        'IntegrationWizardResultModel': IntegrationWizardResultModelToJSON(value['integrationWizardResultModel']),
        'Id': value['id'],
        'State': value['state'],
    };
}

