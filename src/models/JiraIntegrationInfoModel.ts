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
import type { IntegrationUserMappingItemModel } from './IntegrationUserMappingItemModel';
import {
    IntegrationUserMappingItemModelFromJSON,
    IntegrationUserMappingItemModelFromJSONTyped,
    IntegrationUserMappingItemModelToJSON,
} from './IntegrationUserMappingItemModel';
import type { IntegrationWizardResultModel } from './IntegrationWizardResultModel';
import {
    IntegrationWizardResultModelFromJSON,
    IntegrationWizardResultModelFromJSONTyped,
    IntegrationWizardResultModelToJSON,
} from './IntegrationWizardResultModel';
import type { JiraPriorityMapping } from './JiraPriorityMapping';
import {
    JiraPriorityMappingFromJSON,
    JiraPriorityMappingFromJSONTyped,
    JiraPriorityMappingToJSON,
} from './JiraPriorityMapping';

/**
 * The Jira integration info
 * @export
 * @interface JiraIntegrationInfoModel
 */
export interface JiraIntegrationInfoModel {
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    assignedTo?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    assignedToName?: string;
    /**
     * 
     * @type {boolean}
     * @memberof JiraIntegrationInfoModel
     */
    autoAssignToPerson?: boolean;
    /**
     * 
     * @type {number}
     * @memberof JiraIntegrationInfoModel
     */
    dueDays?: number;
    /**
     * 
     * @type {boolean}
     * @memberof JiraIntegrationInfoModel
     */
    readonly isCloud?: boolean;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    issueType: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    issueTypeId?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    labels?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    components?: string;
    /**
     * 
     * @type {Array<IntegrationUserMappingItemModel>}
     * @memberof JiraIntegrationInfoModel
     */
    mappedJiraUsers?: Array<IntegrationUserMappingItemModel>;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    password: string;
    /**
     * Gets or sets the priority.
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    priority?: string;
    /**
     * The issue security level.
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    securityLevel?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    projectKey: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    projectName?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    projectId?: string;
    /**
     * Gets or sets the type of the issue.
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly reopenStatus?: string;
    /**
     * Gets or sets the jira reopen type of the issue.
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    reopenStatusJira?: JiraIntegrationInfoModelReopenStatusJiraEnum;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    reporter?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    reporterName?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    url: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    usernameOrEmail: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    templateType?: JiraIntegrationInfoModelTemplateTypeEnum;
    /**
     * Gets or sets type of the jira epic name
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    epicName?: string;
    /**
     * Gets or sets type of the jira epic name custom field name
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    epicNameCustomFieldName?: string;
    /**
     * Gets or sets type of the jira epic key
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    epicKey?: string;
    /**
     * Gets or sets type of the jira epic key custom field name
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    epicKeyCustomFieldName?: string;
    /**
     * Gets or sets type of the jira epic type
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly epicSelectionType?: JiraIntegrationInfoModelEpicSelectionTypeEnum;
    /**
     * 
     * @type {Array<JiraPriorityMapping>}
     * @memberof JiraIntegrationInfoModel
     */
    priorityMappings?: Array<JiraPriorityMapping>;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly type?: JiraIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof JiraIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof JiraIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof JiraIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof JiraIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}


/**
 * @export
 */
export const JiraIntegrationInfoModelReopenStatusJiraEnum = {
    ToDo: 'ToDo',
    InProgress: 'InProgress'
} as const;
export type JiraIntegrationInfoModelReopenStatusJiraEnum = typeof JiraIntegrationInfoModelReopenStatusJiraEnum[keyof typeof JiraIntegrationInfoModelReopenStatusJiraEnum];

/**
 * @export
 */
export const JiraIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type JiraIntegrationInfoModelTemplateTypeEnum = typeof JiraIntegrationInfoModelTemplateTypeEnum[keyof typeof JiraIntegrationInfoModelTemplateTypeEnum];

/**
 * @export
 */
export const JiraIntegrationInfoModelEpicSelectionTypeEnum = {
    None: 'None',
    EpicName: 'EpicName',
    EpicKey: 'EpicKey'
} as const;
export type JiraIntegrationInfoModelEpicSelectionTypeEnum = typeof JiraIntegrationInfoModelEpicSelectionTypeEnum[keyof typeof JiraIntegrationInfoModelEpicSelectionTypeEnum];

/**
 * @export
 */
export const JiraIntegrationInfoModelTypeEnum = {
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
export type JiraIntegrationInfoModelTypeEnum = typeof JiraIntegrationInfoModelTypeEnum[keyof typeof JiraIntegrationInfoModelTypeEnum];


/**
 * Check if a given object implements the JiraIntegrationInfoModel interface.
 */
export function instanceOfJiraIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "issueType" in value;
    isInstance = isInstance && "password" in value;
    isInstance = isInstance && "projectKey" in value;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "usernameOrEmail" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function JiraIntegrationInfoModelFromJSON(json: any): JiraIntegrationInfoModel {
    return JiraIntegrationInfoModelFromJSONTyped(json, false);
}

export function JiraIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): JiraIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'assignedTo': !exists(json, 'AssignedTo') ? undefined : json['AssignedTo'],
        'assignedToName': !exists(json, 'AssignedToName') ? undefined : json['AssignedToName'],
        'autoAssignToPerson': !exists(json, 'AutoAssignToPerson') ? undefined : json['AutoAssignToPerson'],
        'dueDays': !exists(json, 'DueDays') ? undefined : json['DueDays'],
        'isCloud': !exists(json, 'IsCloud') ? undefined : json['IsCloud'],
        'issueType': json['IssueType'],
        'issueTypeId': !exists(json, 'IssueTypeId') ? undefined : json['IssueTypeId'],
        'labels': !exists(json, 'Labels') ? undefined : json['Labels'],
        'components': !exists(json, 'Components') ? undefined : json['Components'],
        'mappedJiraUsers': !exists(json, 'MappedJiraUsers') ? undefined : ((json['MappedJiraUsers'] as Array<any>).map(IntegrationUserMappingItemModelFromJSON)),
        'password': json['Password'],
        'priority': !exists(json, 'Priority') ? undefined : json['Priority'],
        'securityLevel': !exists(json, 'SecurityLevel') ? undefined : json['SecurityLevel'],
        'projectKey': json['ProjectKey'],
        'projectName': !exists(json, 'ProjectName') ? undefined : json['ProjectName'],
        'projectId': !exists(json, 'ProjectId') ? undefined : json['ProjectId'],
        'reopenStatus': !exists(json, 'ReopenStatus') ? undefined : json['ReopenStatus'],
        'reopenStatusJira': !exists(json, 'ReopenStatusJira') ? undefined : json['ReopenStatusJira'],
        'reporter': !exists(json, 'Reporter') ? undefined : json['Reporter'],
        'reporterName': !exists(json, 'ReporterName') ? undefined : json['ReporterName'],
        'url': json['Url'],
        'usernameOrEmail': json['UsernameOrEmail'],
        'webhookUrl': !exists(json, 'WebhookUrl') ? undefined : json['WebhookUrl'],
        'templateType': !exists(json, 'TemplateType') ? undefined : json['TemplateType'],
        'epicName': !exists(json, 'EpicName') ? undefined : json['EpicName'],
        'epicNameCustomFieldName': !exists(json, 'EpicNameCustomFieldName') ? undefined : json['EpicNameCustomFieldName'],
        'epicKey': !exists(json, 'EpicKey') ? undefined : json['EpicKey'],
        'epicKeyCustomFieldName': !exists(json, 'EpicKeyCustomFieldName') ? undefined : json['EpicKeyCustomFieldName'],
        'epicSelectionType': !exists(json, 'EpicSelectionType') ? undefined : json['EpicSelectionType'],
        'priorityMappings': !exists(json, 'PriorityMappings') ? undefined : ((json['PriorityMappings'] as Array<any>).map(JiraPriorityMappingFromJSON)),
        'type': !exists(json, 'Type') ? undefined : json['Type'],
        'genericErrorMessage': !exists(json, 'GenericErrorMessage') ? undefined : json['GenericErrorMessage'],
        'identifier': !exists(json, 'Identifier') ? undefined : json['Identifier'],
        'testMessageBody': !exists(json, 'TestMessageBody') ? undefined : json['TestMessageBody'],
        'testMessageTitle': !exists(json, 'TestMessageTitle') ? undefined : json['TestMessageTitle'],
        'name': !exists(json, 'Name') ? undefined : json['Name'],
        'integrationVersion': !exists(json, 'IntegrationVersion') ? undefined : json['IntegrationVersion'],
        'accountID': !exists(json, 'AccountID') ? undefined : json['AccountID'],
        'customFields': !exists(json, 'CustomFields') ? undefined : ((json['CustomFields'] as Array<any>).map(IntegrationCustomFieldVmFromJSON)),
        'resolvedStatus': !exists(json, 'ResolvedStatus') ? undefined : json['ResolvedStatus'],
        'titleFormat': json['TitleFormat'],
        'integrationWizardResultModel': !exists(json, 'IntegrationWizardResultModel') ? undefined : IntegrationWizardResultModelFromJSON(json['IntegrationWizardResultModel']),
    };
}

export function JiraIntegrationInfoModelToJSON(value?: JiraIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'AssignedTo': value.assignedTo,
        'AssignedToName': value.assignedToName,
        'AutoAssignToPerson': value.autoAssignToPerson,
        'DueDays': value.dueDays,
        'IssueType': value.issueType,
        'IssueTypeId': value.issueTypeId,
        'Labels': value.labels,
        'Components': value.components,
        'MappedJiraUsers': value.mappedJiraUsers === undefined ? undefined : ((value.mappedJiraUsers as Array<any>).map(IntegrationUserMappingItemModelToJSON)),
        'Password': value.password,
        'Priority': value.priority,
        'SecurityLevel': value.securityLevel,
        'ProjectKey': value.projectKey,
        'ProjectName': value.projectName,
        'ProjectId': value.projectId,
        'ReopenStatusJira': value.reopenStatusJira,
        'Reporter': value.reporter,
        'ReporterName': value.reporterName,
        'Url': value.url,
        'UsernameOrEmail': value.usernameOrEmail,
        'TemplateType': value.templateType,
        'EpicName': value.epicName,
        'EpicNameCustomFieldName': value.epicNameCustomFieldName,
        'EpicKey': value.epicKey,
        'EpicKeyCustomFieldName': value.epicKeyCustomFieldName,
        'PriorityMappings': value.priorityMappings === undefined ? undefined : ((value.priorityMappings as Array<any>).map(JiraPriorityMappingToJSON)),
        'Name': value.name,
        'IntegrationVersion': value.integrationVersion,
        'AccountID': value.accountID,
        'CustomFields': value.customFields === undefined ? undefined : ((value.customFields as Array<any>).map(IntegrationCustomFieldVmToJSON)),
        'ResolvedStatus': value.resolvedStatus,
        'TitleFormat': value.titleFormat,
        'IntegrationWizardResultModel': IntegrationWizardResultModelToJSON(value.integrationWizardResultModel),
    };
}

