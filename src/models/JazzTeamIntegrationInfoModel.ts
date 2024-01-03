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
 * The Jazz Team integration info
 * @export
 * @interface JazzTeamIntegrationInfoModel
 */
export interface JazzTeamIntegrationInfoModel {
    /**
     * Jazz Team base URL.
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    serverURL: string;
    /**
     * The username of the user.
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    username: string;
    /**
     * The password of the user.
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    password: string;
    /**
     * The Id of Project Area
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    projectAreaId: string;
    /**
     * Category name for work items.
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    categoryName: string;
    /**
     * The work item tags. To add more than one tag, separate each one with a space ( ). For example: tag1 tag2
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    tags?: string;
    /**
     * This is the number of days from the date of the work item was created to the day of it's due.
     * @type {number}
     * @memberof JazzTeamIntegrationInfoModel
     */
    dueDays?: number;
    /**
     * Severity level for work items.
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    severity?: JazzTeamIntegrationInfoModelSeverityEnum;
    /**
     * Priority level for work items.
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    priority?: JazzTeamIntegrationInfoModelPriorityEnum;
    /**
     * Type for work items.
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    workItemType?: JazzTeamIntegrationInfoModelWorkItemTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    templateType?: JazzTeamIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    readonly type?: JazzTeamIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof JazzTeamIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof JazzTeamIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof JazzTeamIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof JazzTeamIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}


/**
 * @export
 */
export const JazzTeamIntegrationInfoModelSeverityEnum = {
    Blocker: 'Blocker',
    Critical: 'Critical',
    Major: 'Major',
    Normal: 'Normal',
    Minor: 'Minor',
    Unclassified: 'Unclassified'
} as const;
export type JazzTeamIntegrationInfoModelSeverityEnum = typeof JazzTeamIntegrationInfoModelSeverityEnum[keyof typeof JazzTeamIntegrationInfoModelSeverityEnum];

/**
 * @export
 */
export const JazzTeamIntegrationInfoModelPriorityEnum = {
    High: 'High',
    Medium: 'Medium',
    Low: 'Low',
    Unassigned: 'Unassigned'
} as const;
export type JazzTeamIntegrationInfoModelPriorityEnum = typeof JazzTeamIntegrationInfoModelPriorityEnum[keyof typeof JazzTeamIntegrationInfoModelPriorityEnum];

/**
 * @export
 */
export const JazzTeamIntegrationInfoModelWorkItemTypeEnum = {
    Task: 'Task',
    Defect: 'Defect'
} as const;
export type JazzTeamIntegrationInfoModelWorkItemTypeEnum = typeof JazzTeamIntegrationInfoModelWorkItemTypeEnum[keyof typeof JazzTeamIntegrationInfoModelWorkItemTypeEnum];

/**
 * @export
 */
export const JazzTeamIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type JazzTeamIntegrationInfoModelTemplateTypeEnum = typeof JazzTeamIntegrationInfoModelTemplateTypeEnum[keyof typeof JazzTeamIntegrationInfoModelTemplateTypeEnum];

/**
 * @export
 */
export const JazzTeamIntegrationInfoModelTypeEnum = {
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
export type JazzTeamIntegrationInfoModelTypeEnum = typeof JazzTeamIntegrationInfoModelTypeEnum[keyof typeof JazzTeamIntegrationInfoModelTypeEnum];


/**
 * Check if a given object implements the JazzTeamIntegrationInfoModel interface.
 */
export function instanceOfJazzTeamIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "serverURL" in value;
    isInstance = isInstance && "username" in value;
    isInstance = isInstance && "password" in value;
    isInstance = isInstance && "projectAreaId" in value;
    isInstance = isInstance && "categoryName" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function JazzTeamIntegrationInfoModelFromJSON(json: any): JazzTeamIntegrationInfoModel {
    return JazzTeamIntegrationInfoModelFromJSONTyped(json, false);
}

export function JazzTeamIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): JazzTeamIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'serverURL': json['ServerURL'],
        'username': json['Username'],
        'password': json['Password'],
        'projectAreaId': json['ProjectAreaId'],
        'categoryName': json['CategoryName'],
        'tags': !exists(json, 'Tags') ? undefined : json['Tags'],
        'dueDays': !exists(json, 'DueDays') ? undefined : json['DueDays'],
        'severity': !exists(json, 'Severity') ? undefined : json['Severity'],
        'priority': !exists(json, 'Priority') ? undefined : json['Priority'],
        'workItemType': !exists(json, 'WorkItemType') ? undefined : json['WorkItemType'],
        'templateType': !exists(json, 'TemplateType') ? undefined : json['TemplateType'],
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
        'reopenStatus': !exists(json, 'ReopenStatus') ? undefined : json['ReopenStatus'],
        'resolvedStatus': !exists(json, 'ResolvedStatus') ? undefined : json['ResolvedStatus'],
        'titleFormat': json['TitleFormat'],
        'integrationWizardResultModel': !exists(json, 'IntegrationWizardResultModel') ? undefined : IntegrationWizardResultModelFromJSON(json['IntegrationWizardResultModel']),
    };
}

export function JazzTeamIntegrationInfoModelToJSON(value?: JazzTeamIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'ServerURL': value.serverURL,
        'Username': value.username,
        'Password': value.password,
        'ProjectAreaId': value.projectAreaId,
        'CategoryName': value.categoryName,
        'Tags': value.tags,
        'DueDays': value.dueDays,
        'Severity': value.severity,
        'Priority': value.priority,
        'WorkItemType': value.workItemType,
        'TemplateType': value.templateType,
        'Name': value.name,
        'IntegrationVersion': value.integrationVersion,
        'AccountID': value.accountID,
        'CustomFields': value.customFields === undefined ? undefined : ((value.customFields as Array<any>).map(IntegrationCustomFieldVmToJSON)),
        'ReopenStatus': value.reopenStatus,
        'ResolvedStatus': value.resolvedStatus,
        'TitleFormat': value.titleFormat,
        'IntegrationWizardResultModel': IntegrationWizardResultModelToJSON(value.integrationWizardResultModel),
    };
}
