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
 * The FogBugz integration info
 * @export
 * @interface FogBugzIntegrationInfoModel
 */
export interface FogBugzIntegrationInfoModel {
    /**
     * Gets or sets the area to assign cases to.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    area?: string;
    /**
     * Gets or sets the assigned to.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    assignedTo?: string;
    /**
     * Gets or sets the category to assign cases to.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    category: string;
    /**
     * Gets or sets the milestone to assign cases to.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    milestone?: string;
    /**
     * Gets or sets the project to assign cases to.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    project?: string;
    /**
     * Gets or sets the tags.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    tags?: string;
    /**
     * Gets or sets the FogBugz API token for the user.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    token: string;
    /**
     * Gets or sets the URL.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    url: string;
    /**
     * Gets FogBugz web hook URL.
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly type?: FogBugzIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof FogBugzIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof FogBugzIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    templateType?: FogBugzIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof FogBugzIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    id?: string;
    /**
     * 
     * @type {string}
     * @memberof FogBugzIntegrationInfoModel
     */
    state?: FogBugzIntegrationInfoModelStateEnum;
}


/**
 * @export
 */
export const FogBugzIntegrationInfoModelTypeEnum = {
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
export type FogBugzIntegrationInfoModelTypeEnum = typeof FogBugzIntegrationInfoModelTypeEnum[keyof typeof FogBugzIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const FogBugzIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type FogBugzIntegrationInfoModelTemplateTypeEnum = typeof FogBugzIntegrationInfoModelTemplateTypeEnum[keyof typeof FogBugzIntegrationInfoModelTemplateTypeEnum];

/**
 * @export
 */
export const FogBugzIntegrationInfoModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
} as const;
export type FogBugzIntegrationInfoModelStateEnum = typeof FogBugzIntegrationInfoModelStateEnum[keyof typeof FogBugzIntegrationInfoModelStateEnum];


/**
 * Check if a given object implements the FogBugzIntegrationInfoModel interface.
 */
export function instanceOfFogBugzIntegrationInfoModel(value: object): boolean {
    if (!('category' in value)) return false;
    if (!('token' in value)) return false;
    if (!('url' in value)) return false;
    if (!('titleFormat' in value)) return false;
    return true;
}

export function FogBugzIntegrationInfoModelFromJSON(json: any): FogBugzIntegrationInfoModel {
    return FogBugzIntegrationInfoModelFromJSONTyped(json, false);
}

export function FogBugzIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): FogBugzIntegrationInfoModel {
    if (json == null) {
        return json;
    }
    return {
        
        'area': json['Area'] == null ? undefined : json['Area'],
        'assignedTo': json['AssignedTo'] == null ? undefined : json['AssignedTo'],
        'category': json['Category'],
        'milestone': json['Milestone'] == null ? undefined : json['Milestone'],
        'project': json['Project'] == null ? undefined : json['Project'],
        'tags': json['Tags'] == null ? undefined : json['Tags'],
        'token': json['Token'],
        'url': json['Url'],
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

export function FogBugzIntegrationInfoModelToJSON(value?: Omit<FogBugzIntegrationInfoModel, 'WebhookUrl'|'Type'|'GenericErrorMessage'|'Identifier'|'TestMessageBody'|'TestMessageTitle'> | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Area': value['area'],
        'AssignedTo': value['assignedTo'],
        'Category': value['category'],
        'Milestone': value['milestone'],
        'Project': value['project'],
        'Tags': value['tags'],
        'Token': value['token'],
        'Url': value['url'],
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

