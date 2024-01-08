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
import type { TrelloBoard } from './TrelloBoard';
import {
    TrelloBoardFromJSON,
    TrelloBoardFromJSONTyped,
    TrelloBoardToJSON,
} from './TrelloBoard';
import type { TrelloLabel } from './TrelloLabel';
import {
    TrelloLabelFromJSON,
    TrelloLabelFromJSONTyped,
    TrelloLabelToJSON,
} from './TrelloLabel';
import type { TrelloList } from './TrelloList';
import {
    TrelloListFromJSON,
    TrelloListFromJSONTyped,
    TrelloListToJSON,
} from './TrelloList';
import type { TrelloMember } from './TrelloMember';
import {
    TrelloMemberFromJSON,
    TrelloMemberFromJSONTyped,
    TrelloMemberToJSON,
} from './TrelloMember';

/**
 * The Trello integration info
 * @export
 * @interface TrelloIntegrationInfoModel
 */
export interface TrelloIntegrationInfoModel {
    /**
     * The API Key for API requests.
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    apiKey: string;
    /**
     * The Token ID identifier.
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    token: string;
    /**
     * The List identifier.
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    listId: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof TrelloIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
    /**
     * The Board identifier.
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    boardId: string;
    /**
     * The TrelloBoard List.
     * @type {Array<TrelloBoard>}
     * @memberof TrelloIntegrationInfoModel
     */
    boardIds?: Array<TrelloBoard>;
    /**
     * The TrelloList List.
     * @type {Array<TrelloList>}
     * @memberof TrelloIntegrationInfoModel
     */
    lists?: Array<TrelloList>;
    /**
     * The TrelloMember List.
     * @type {Array<TrelloMember>}
     * @memberof TrelloIntegrationInfoModel
     */
    members?: Array<TrelloMember>;
    /**
     * The TrelloLabel List.
     * @type {Array<TrelloLabel>}
     * @memberof TrelloIntegrationInfoModel
     */
    labels?: Array<TrelloLabel>;
    /**
     * Comma-separated Member  identifiers.
     * @type {Array<string>}
     * @memberof TrelloIntegrationInfoModel
     */
    memberIds?: Array<string>;
    /**
     * Comma-separated Label identifiers.
     * @type {Array<string>}
     * @memberof TrelloIntegrationInfoModel
     */
    labelIds?: Array<string>;
    /**
     * Comma-separated Label to convert string identifiers.
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    readonly labelIdsSelected?: string;
    /**
     * Comma-separated Member to convert string identifiers.
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    readonly memberIdsSelected?: string;
    /**
     * The days when incident is due from the time that issue is created on.
     * @type {number}
     * @memberof TrelloIntegrationInfoModel
     */
    dueDays: number;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    readonly type?: TrelloIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof TrelloIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof TrelloIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    templateType?: TrelloIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof TrelloIntegrationInfoModel
     */
    titleFormat: string;
}


/**
 * @export
 */
export const TrelloIntegrationInfoModelTypeEnum = {
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
export type TrelloIntegrationInfoModelTypeEnum = typeof TrelloIntegrationInfoModelTypeEnum[keyof typeof TrelloIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const TrelloIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type TrelloIntegrationInfoModelTemplateTypeEnum = typeof TrelloIntegrationInfoModelTemplateTypeEnum[keyof typeof TrelloIntegrationInfoModelTemplateTypeEnum];


/**
 * Check if a given object implements the TrelloIntegrationInfoModel interface.
 */
export function instanceOfTrelloIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "apiKey" in value;
    isInstance = isInstance && "token" in value;
    isInstance = isInstance && "listId" in value;
    isInstance = isInstance && "boardId" in value;
    isInstance = isInstance && "dueDays" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function TrelloIntegrationInfoModelFromJSON(json: any): TrelloIntegrationInfoModel {
    return TrelloIntegrationInfoModelFromJSONTyped(json, false);
}

export function TrelloIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): TrelloIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'apiKey': json['ApiKey'],
        'token': json['Token'],
        'listId': json['ListId'],
        'integrationWizardResultModel': !exists(json, 'IntegrationWizardResultModel') ? undefined : IntegrationWizardResultModelFromJSON(json['IntegrationWizardResultModel']),
        'boardId': json['BoardId'],
        'boardIds': !exists(json, 'BoardIds') ? undefined : ((json['BoardIds'] as Array<any>).map(TrelloBoardFromJSON)),
        'lists': !exists(json, 'Lists') ? undefined : ((json['Lists'] as Array<any>).map(TrelloListFromJSON)),
        'members': !exists(json, 'Members') ? undefined : ((json['Members'] as Array<any>).map(TrelloMemberFromJSON)),
        'labels': !exists(json, 'Labels') ? undefined : ((json['Labels'] as Array<any>).map(TrelloLabelFromJSON)),
        'memberIds': !exists(json, 'MemberIds') ? undefined : json['MemberIds'],
        'labelIds': !exists(json, 'LabelIds') ? undefined : json['LabelIds'],
        'labelIdsSelected': !exists(json, 'LabelIdsSelected') ? undefined : json['LabelIdsSelected'],
        'memberIdsSelected': !exists(json, 'MemberIdsSelected') ? undefined : json['MemberIdsSelected'],
        'dueDays': json['DueDays'],
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
    };
}

export function TrelloIntegrationInfoModelToJSON(value?: TrelloIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'ApiKey': value.apiKey,
        'Token': value.token,
        'ListId': value.listId,
        'IntegrationWizardResultModel': IntegrationWizardResultModelToJSON(value.integrationWizardResultModel),
        'BoardId': value.boardId,
        'BoardIds': value.boardIds === undefined ? undefined : ((value.boardIds as Array<any>).map(TrelloBoardToJSON)),
        'Lists': value.lists === undefined ? undefined : ((value.lists as Array<any>).map(TrelloListToJSON)),
        'Members': value.members === undefined ? undefined : ((value.members as Array<any>).map(TrelloMemberToJSON)),
        'Labels': value.labels === undefined ? undefined : ((value.labels as Array<any>).map(TrelloLabelToJSON)),
        'MemberIds': value.memberIds,
        'LabelIds': value.labelIds,
        'DueDays': value.dueDays,
        'Name': value.name,
        'IntegrationVersion': value.integrationVersion,
        'AccountID': value.accountID,
        'CustomFields': value.customFields === undefined ? undefined : ((value.customFields as Array<any>).map(IntegrationCustomFieldVmToJSON)),
        'TemplateType': value.templateType,
        'ReopenStatus': value.reopenStatus,
        'ResolvedStatus': value.resolvedStatus,
        'TitleFormat': value.titleFormat,
    };
}

