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
 * The Slack integration info
 * @export
 * @interface SlackIntegrationInfoModel
 */
export interface SlackIntegrationInfoModel {
    /**
     * Gets or sets the Webhook URL.
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    incomingWebhookUrl: string;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    readonly type?: SlackIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof SlackIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof SlackIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    templateType?: SlackIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof SlackIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    id?: string;
    /**
     * 
     * @type {string}
     * @memberof SlackIntegrationInfoModel
     */
    state?: SlackIntegrationInfoModelStateEnum;
}


/**
 * @export
 */
export const SlackIntegrationInfoModelTypeEnum = {
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
export type SlackIntegrationInfoModelTypeEnum = typeof SlackIntegrationInfoModelTypeEnum[keyof typeof SlackIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const SlackIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type SlackIntegrationInfoModelTemplateTypeEnum = typeof SlackIntegrationInfoModelTemplateTypeEnum[keyof typeof SlackIntegrationInfoModelTemplateTypeEnum];

/**
 * @export
 */
export const SlackIntegrationInfoModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
} as const;
export type SlackIntegrationInfoModelStateEnum = typeof SlackIntegrationInfoModelStateEnum[keyof typeof SlackIntegrationInfoModelStateEnum];


/**
 * Check if a given object implements the SlackIntegrationInfoModel interface.
 */
export function instanceOfSlackIntegrationInfoModel(value: object): boolean {
    if (!('incomingWebhookUrl' in value)) return false;
    if (!('titleFormat' in value)) return false;
    return true;
}

export function SlackIntegrationInfoModelFromJSON(json: any): SlackIntegrationInfoModel {
    return SlackIntegrationInfoModelFromJSONTyped(json, false);
}

export function SlackIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): SlackIntegrationInfoModel {
    if (json == null) {
        return json;
    }
    return {
        
        'incomingWebhookUrl': json['IncomingWebhookUrl'],
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

export function SlackIntegrationInfoModelToJSON(value?: Omit<SlackIntegrationInfoModel, 'Type'|'GenericErrorMessage'|'Identifier'|'TestMessageBody'|'TestMessageTitle'|'WebhookUrl'> | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'IncomingWebhookUrl': value['incomingWebhookUrl'],
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

