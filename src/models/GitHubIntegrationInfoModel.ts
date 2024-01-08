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
 * The GitHub integration info
 * @export
 * @interface GitHubIntegrationInfoModel
 */
export interface GitHubIntegrationInfoModel {
    /**
     * Gets or sets the access token.
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    accessToken: string;
    /**
     * The Server URL.
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    serverUrl: string;
    /**
     * Gets or sets the assignee.
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    assignee?: string;
    /**
     * Gets or sets the labels.
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    labels?: string;
    /**
     * Gets or sets the repository.
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    repository: string;
    /**
     * Gets or sets the username.
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    username: string;
    /**
     * Gets or sets the organization.
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    organization?: string;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    readonly type?: GitHubIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof GitHubIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof GitHubIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    templateType?: GitHubIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof GitHubIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof GitHubIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}


/**
 * @export
 */
export const GitHubIntegrationInfoModelTypeEnum = {
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
export type GitHubIntegrationInfoModelTypeEnum = typeof GitHubIntegrationInfoModelTypeEnum[keyof typeof GitHubIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const GitHubIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type GitHubIntegrationInfoModelTemplateTypeEnum = typeof GitHubIntegrationInfoModelTemplateTypeEnum[keyof typeof GitHubIntegrationInfoModelTemplateTypeEnum];


/**
 * Check if a given object implements the GitHubIntegrationInfoModel interface.
 */
export function instanceOfGitHubIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "accessToken" in value;
    isInstance = isInstance && "serverUrl" in value;
    isInstance = isInstance && "repository" in value;
    isInstance = isInstance && "username" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function GitHubIntegrationInfoModelFromJSON(json: any): GitHubIntegrationInfoModel {
    return GitHubIntegrationInfoModelFromJSONTyped(json, false);
}

export function GitHubIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): GitHubIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'accessToken': json['AccessToken'],
        'serverUrl': json['ServerUrl'],
        'assignee': !exists(json, 'Assignee') ? undefined : json['Assignee'],
        'labels': !exists(json, 'Labels') ? undefined : json['Labels'],
        'repository': json['Repository'],
        'username': json['Username'],
        'organization': !exists(json, 'Organization') ? undefined : json['Organization'],
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

export function GitHubIntegrationInfoModelToJSON(value?: GitHubIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'AccessToken': value.accessToken,
        'ServerUrl': value.serverUrl,
        'Assignee': value.assignee,
        'Labels': value.labels,
        'Repository': value.repository,
        'Username': value.username,
        'Organization': value.organization,
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

