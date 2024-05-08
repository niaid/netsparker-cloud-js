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
import type { FreshServiceRequesterUser } from './FreshServiceRequesterUser';
import {
    FreshServiceRequesterUserFromJSON,
    FreshServiceRequesterUserFromJSONTyped,
    FreshServiceRequesterUserToJSON,
} from './FreshServiceRequesterUser';
import type { FreshServiceUserAgent } from './FreshServiceUserAgent';
import {
    FreshServiceUserAgentFromJSON,
    FreshServiceUserAgentFromJSONTyped,
    FreshServiceUserAgentToJSON,
} from './FreshServiceUserAgent';
import type { FreshserviceEntity } from './FreshserviceEntity';
import {
    FreshserviceEntityFromJSON,
    FreshserviceEntityFromJSONTyped,
    FreshserviceEntityToJSON,
} from './FreshserviceEntity';
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
 * The Freshservice integration info
 * @export
 * @interface FreshserviceIntegrationInfoModel
 */
export interface FreshserviceIntegrationInfoModel {
    /**
     * The server URL to which to send problems.
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    serverUrl: string;
    /**
     * The API key for authentication.
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    apiKey: string;
    /**
     * The user identifier who reports the problem.
     * @type {number}
     * @memberof FreshserviceIntegrationInfoModel
     */
    requesterId: number;
    /**
     * The group identifier to which the problem is assigned.
     * @type {number}
     * @memberof FreshserviceIntegrationInfoModel
     */
    groupId?: number;
    /**
     * The agent identifier to whom the problem is assigned.
     * @type {number}
     * @memberof FreshserviceIntegrationInfoModel
     */
    agentId?: number;
    /**
     * The priority identifier of the problem.
     * @type {number}
     * @memberof FreshserviceIntegrationInfoModel
     */
    priorityId?: number;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof FreshserviceIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
    /**
     * The Requesters List.
     * @type {Array<FreshServiceRequesterUser>}
     * @memberof FreshserviceIntegrationInfoModel
     */
    requesters?: Array<FreshServiceRequesterUser>;
    /**
     * The Groups List.
     * @type {Array<FreshserviceEntity>}
     * @memberof FreshserviceIntegrationInfoModel
     */
    groups?: Array<FreshserviceEntity>;
    /**
     * The Agents List.
     * @type {Array<FreshServiceUserAgent>}
     * @memberof FreshserviceIntegrationInfoModel
     */
    agents?: Array<FreshServiceUserAgent>;
    /**
     * The Priorities List.
     * @type {Array<FreshserviceEntity>}
     * @memberof FreshserviceIntegrationInfoModel
     */
    priorities?: Array<FreshserviceEntity>;
    /**
     * The number of days from the date the problem was created to the date it's due.
     * @type {number}
     * @memberof FreshserviceIntegrationInfoModel
     */
    dueDays?: number;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    readonly type?: FreshserviceIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof FreshserviceIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof FreshserviceIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    templateType?: FreshserviceIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    id?: string;
    /**
     * 
     * @type {string}
     * @memberof FreshserviceIntegrationInfoModel
     */
    state?: FreshserviceIntegrationInfoModelStateEnum;
}


/**
 * @export
 */
export const FreshserviceIntegrationInfoModelTypeEnum = {
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
export type FreshserviceIntegrationInfoModelTypeEnum = typeof FreshserviceIntegrationInfoModelTypeEnum[keyof typeof FreshserviceIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const FreshserviceIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type FreshserviceIntegrationInfoModelTemplateTypeEnum = typeof FreshserviceIntegrationInfoModelTemplateTypeEnum[keyof typeof FreshserviceIntegrationInfoModelTemplateTypeEnum];

/**
 * @export
 */
export const FreshserviceIntegrationInfoModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
} as const;
export type FreshserviceIntegrationInfoModelStateEnum = typeof FreshserviceIntegrationInfoModelStateEnum[keyof typeof FreshserviceIntegrationInfoModelStateEnum];


/**
 * Check if a given object implements the FreshserviceIntegrationInfoModel interface.
 */
export function instanceOfFreshserviceIntegrationInfoModel(value: object): boolean {
    if (!('serverUrl' in value)) return false;
    if (!('apiKey' in value)) return false;
    if (!('requesterId' in value)) return false;
    if (!('titleFormat' in value)) return false;
    return true;
}

export function FreshserviceIntegrationInfoModelFromJSON(json: any): FreshserviceIntegrationInfoModel {
    return FreshserviceIntegrationInfoModelFromJSONTyped(json, false);
}

export function FreshserviceIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): FreshserviceIntegrationInfoModel {
    if (json == null) {
        return json;
    }
    return {
        
        'serverUrl': json['ServerUrl'],
        'apiKey': json['ApiKey'],
        'requesterId': json['RequesterId'],
        'groupId': json['GroupId'] == null ? undefined : json['GroupId'],
        'agentId': json['AgentId'] == null ? undefined : json['AgentId'],
        'priorityId': json['PriorityId'] == null ? undefined : json['PriorityId'],
        'integrationWizardResultModel': json['IntegrationWizardResultModel'] == null ? undefined : IntegrationWizardResultModelFromJSON(json['IntegrationWizardResultModel']),
        'requesters': json['Requesters'] == null ? undefined : ((json['Requesters'] as Array<any>).map(FreshServiceRequesterUserFromJSON)),
        'groups': json['Groups'] == null ? undefined : ((json['Groups'] as Array<any>).map(FreshserviceEntityFromJSON)),
        'agents': json['Agents'] == null ? undefined : ((json['Agents'] as Array<any>).map(FreshServiceUserAgentFromJSON)),
        'priorities': json['Priorities'] == null ? undefined : ((json['Priorities'] as Array<any>).map(FreshserviceEntityFromJSON)),
        'dueDays': json['DueDays'] == null ? undefined : json['DueDays'],
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
        'id': json['Id'] == null ? undefined : json['Id'],
        'state': json['State'] == null ? undefined : json['State'],
    };
}

export function FreshserviceIntegrationInfoModelToJSON(value?: Omit<FreshserviceIntegrationInfoModel, 'Type'|'GenericErrorMessage'|'Identifier'|'TestMessageBody'|'TestMessageTitle'|'WebhookUrl'> | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'ServerUrl': value['serverUrl'],
        'ApiKey': value['apiKey'],
        'RequesterId': value['requesterId'],
        'GroupId': value['groupId'],
        'AgentId': value['agentId'],
        'PriorityId': value['priorityId'],
        'IntegrationWizardResultModel': IntegrationWizardResultModelToJSON(value['integrationWizardResultModel']),
        'Requesters': value['requesters'] == null ? undefined : ((value['requesters'] as Array<any>).map(FreshServiceRequesterUserToJSON)),
        'Groups': value['groups'] == null ? undefined : ((value['groups'] as Array<any>).map(FreshserviceEntityToJSON)),
        'Agents': value['agents'] == null ? undefined : ((value['agents'] as Array<any>).map(FreshServiceUserAgentToJSON)),
        'Priorities': value['priorities'] == null ? undefined : ((value['priorities'] as Array<any>).map(FreshserviceEntityToJSON)),
        'DueDays': value['dueDays'],
        'Name': value['name'],
        'IntegrationVersion': value['integrationVersion'],
        'AccountID': value['accountID'],
        'CustomFields': value['customFields'] == null ? undefined : ((value['customFields'] as Array<any>).map(IntegrationCustomFieldVmToJSON)),
        'TemplateType': value['templateType'],
        'ReopenStatus': value['reopenStatus'],
        'ResolvedStatus': value['resolvedStatus'],
        'TitleFormat': value['titleFormat'],
        'Id': value['id'],
        'State': value['state'],
    };
}

