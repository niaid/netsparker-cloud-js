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
 * The Pivotal integration info
 * @export
 * @interface PivotalTrackerIntegrationInfoModel
 */
export interface PivotalTrackerIntegrationInfoModel {
    /**
     * API Access Key for authentication.
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    apiToken: string;
    /**
     * The project identifer to create issue in.
     * @type {number}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    projectId: number;
    /**
     * The project identifer to create issue in.
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    storyType: PivotalTrackerIntegrationInfoModelStoryTypeEnum;
    /**
     * The category identifier.
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    ownerIds?: string;
    /**
     * The category identifier.
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    labels?: string;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    readonly type?: PivotalTrackerIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    templateType?: PivotalTrackerIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof PivotalTrackerIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}


/**
 * @export
 */
export const PivotalTrackerIntegrationInfoModelStoryTypeEnum = {
    Bug: 'Bug',
    Feature: 'Feature',
    Chore: 'Chore',
    Release: 'Release'
} as const;
export type PivotalTrackerIntegrationInfoModelStoryTypeEnum = typeof PivotalTrackerIntegrationInfoModelStoryTypeEnum[keyof typeof PivotalTrackerIntegrationInfoModelStoryTypeEnum];

/**
 * @export
 */
export const PivotalTrackerIntegrationInfoModelTypeEnum = {
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
export type PivotalTrackerIntegrationInfoModelTypeEnum = typeof PivotalTrackerIntegrationInfoModelTypeEnum[keyof typeof PivotalTrackerIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const PivotalTrackerIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type PivotalTrackerIntegrationInfoModelTemplateTypeEnum = typeof PivotalTrackerIntegrationInfoModelTemplateTypeEnum[keyof typeof PivotalTrackerIntegrationInfoModelTemplateTypeEnum];


/**
 * Check if a given object implements the PivotalTrackerIntegrationInfoModel interface.
 */
export function instanceOfPivotalTrackerIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "apiToken" in value;
    isInstance = isInstance && "projectId" in value;
    isInstance = isInstance && "storyType" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function PivotalTrackerIntegrationInfoModelFromJSON(json: any): PivotalTrackerIntegrationInfoModel {
    return PivotalTrackerIntegrationInfoModelFromJSONTyped(json, false);
}

export function PivotalTrackerIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): PivotalTrackerIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'apiToken': json['ApiToken'],
        'projectId': json['ProjectId'],
        'storyType': json['StoryType'],
        'ownerIds': !exists(json, 'OwnerIds') ? undefined : json['OwnerIds'],
        'labels': !exists(json, 'Labels') ? undefined : json['Labels'],
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

export function PivotalTrackerIntegrationInfoModelToJSON(value?: PivotalTrackerIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'ApiToken': value.apiToken,
        'ProjectId': value.projectId,
        'StoryType': value.storyType,
        'OwnerIds': value.ownerIds,
        'Labels': value.labels,
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

