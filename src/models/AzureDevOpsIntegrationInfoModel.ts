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
 * The Azure DevOps integration info
 * @export
 * @interface AzureDevOpsIntegrationInfoModel
 */
export interface AzureDevOpsIntegrationInfoModel {
    /**
     * Gets or sets the password.
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    password: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    username?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    assignedTo?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    domain?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    projectUri: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    tags?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    workItemTypeName: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    readonly type?: AzureDevOpsIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    templateType?: AzureDevOpsIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    id?: string;
    /**
     * 
     * @type {string}
     * @memberof AzureDevOpsIntegrationInfoModel
     */
    state?: AzureDevOpsIntegrationInfoModelStateEnum;
}


/**
 * @export
 */
export const AzureDevOpsIntegrationInfoModelTypeEnum = {
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
export type AzureDevOpsIntegrationInfoModelTypeEnum = typeof AzureDevOpsIntegrationInfoModelTypeEnum[keyof typeof AzureDevOpsIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const AzureDevOpsIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type AzureDevOpsIntegrationInfoModelTemplateTypeEnum = typeof AzureDevOpsIntegrationInfoModelTemplateTypeEnum[keyof typeof AzureDevOpsIntegrationInfoModelTemplateTypeEnum];

/**
 * @export
 */
export const AzureDevOpsIntegrationInfoModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
} as const;
export type AzureDevOpsIntegrationInfoModelStateEnum = typeof AzureDevOpsIntegrationInfoModelStateEnum[keyof typeof AzureDevOpsIntegrationInfoModelStateEnum];


/**
 * Check if a given object implements the AzureDevOpsIntegrationInfoModel interface.
 */
export function instanceOfAzureDevOpsIntegrationInfoModel(value: object): boolean {
    if (!('password' in value)) return false;
    if (!('projectUri' in value)) return false;
    if (!('workItemTypeName' in value)) return false;
    if (!('titleFormat' in value)) return false;
    return true;
}

export function AzureDevOpsIntegrationInfoModelFromJSON(json: any): AzureDevOpsIntegrationInfoModel {
    return AzureDevOpsIntegrationInfoModelFromJSONTyped(json, false);
}

export function AzureDevOpsIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AzureDevOpsIntegrationInfoModel {
    if (json == null) {
        return json;
    }
    return {
        
        'password': json['Password'],
        'username': json['Username'] == null ? undefined : json['Username'],
        'assignedTo': json['AssignedTo'] == null ? undefined : json['AssignedTo'],
        'domain': json['Domain'] == null ? undefined : json['Domain'],
        'projectUri': json['ProjectUri'],
        'tags': json['Tags'] == null ? undefined : json['Tags'],
        'workItemTypeName': json['WorkItemTypeName'],
        'webhookUrl': json['WebhookUrl'] == null ? undefined : json['WebhookUrl'],
        'type': json['Type'] == null ? undefined : json['Type'],
        'genericErrorMessage': json['GenericErrorMessage'] == null ? undefined : json['GenericErrorMessage'],
        'identifier': json['Identifier'] == null ? undefined : json['Identifier'],
        'testMessageBody': json['TestMessageBody'] == null ? undefined : json['TestMessageBody'],
        'testMessageTitle': json['TestMessageTitle'] == null ? undefined : json['TestMessageTitle'],
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

export function AzureDevOpsIntegrationInfoModelToJSON(value?: Omit<AzureDevOpsIntegrationInfoModel, 'WebhookUrl'|'Type'|'GenericErrorMessage'|'Identifier'|'TestMessageBody'|'TestMessageTitle'> | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Password': value['password'],
        'Username': value['username'],
        'AssignedTo': value['assignedTo'],
        'Domain': value['domain'],
        'ProjectUri': value['projectUri'],
        'Tags': value['tags'],
        'WorkItemTypeName': value['workItemTypeName'],
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

