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
import type { CustomHttpHeaderModel } from './CustomHttpHeaderModel';
import {
    CustomHttpHeaderModelFromJSON,
    CustomHttpHeaderModelFromJSONTyped,
    CustomHttpHeaderModelToJSON,
} from './CustomHttpHeaderModel';
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
 * The Webhook integration info
 * @export
 * @interface WebhookIntegrationInfoModel
 */
export interface WebhookIntegrationInfoModel {
    /**
     * The HTTP method that indicates the action to be performed on a resource for the request.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    httpMethodType?: WebhookIntegrationInfoModelHttpMethodTypeEnum;
    /**
     * This is the data format in which requests are sent.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    parameterType?: WebhookIntegrationInfoModelParameterTypeEnum;
    /**
     * The URL to which issues should be sent.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    url: string;
    /**
     * The parameter name of the issue.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    issue?: string;
    /**
     * Gets or sets the Http Header.
     * @type {Array<CustomHttpHeaderModel>}
     * @memberof WebhookIntegrationInfoModel
     */
    customHttpHeaderModels?: Array<CustomHttpHeaderModel>;
    /**
     * The parameter name of the issue title.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    title?: string;
    /**
     * The parameter name of the issue body.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    body?: string;
    /**
     * The Username for the HTTP authentication.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    username?: string;
    /**
     * The Password for the HTTP authentication.
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    password?: string;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly type?: WebhookIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof WebhookIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof WebhookIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    templateType?: WebhookIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof WebhookIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof WebhookIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}


/**
 * @export
 */
export const WebhookIntegrationInfoModelHttpMethodTypeEnum = {
    Get: 'Get',
    Post: 'Post',
    Put: 'Put'
} as const;
export type WebhookIntegrationInfoModelHttpMethodTypeEnum = typeof WebhookIntegrationInfoModelHttpMethodTypeEnum[keyof typeof WebhookIntegrationInfoModelHttpMethodTypeEnum];

/**
 * @export
 */
export const WebhookIntegrationInfoModelParameterTypeEnum = {
    Form: 'Form',
    Json: 'Json',
    Xml: 'Xml',
    QueryString: 'QueryString'
} as const;
export type WebhookIntegrationInfoModelParameterTypeEnum = typeof WebhookIntegrationInfoModelParameterTypeEnum[keyof typeof WebhookIntegrationInfoModelParameterTypeEnum];

/**
 * @export
 */
export const WebhookIntegrationInfoModelTypeEnum = {
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
export type WebhookIntegrationInfoModelTypeEnum = typeof WebhookIntegrationInfoModelTypeEnum[keyof typeof WebhookIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const WebhookIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type WebhookIntegrationInfoModelTemplateTypeEnum = typeof WebhookIntegrationInfoModelTemplateTypeEnum[keyof typeof WebhookIntegrationInfoModelTemplateTypeEnum];


/**
 * Check if a given object implements the WebhookIntegrationInfoModel interface.
 */
export function instanceOfWebhookIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function WebhookIntegrationInfoModelFromJSON(json: any): WebhookIntegrationInfoModel {
    return WebhookIntegrationInfoModelFromJSONTyped(json, false);
}

export function WebhookIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): WebhookIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'httpMethodType': !exists(json, 'HttpMethodType') ? undefined : json['HttpMethodType'],
        'parameterType': !exists(json, 'ParameterType') ? undefined : json['ParameterType'],
        'url': json['Url'],
        'issue': !exists(json, 'Issue') ? undefined : json['Issue'],
        'customHttpHeaderModels': !exists(json, 'CustomHttpHeaderModels') ? undefined : ((json['CustomHttpHeaderModels'] as Array<any>).map(CustomHttpHeaderModelFromJSON)),
        'title': !exists(json, 'Title') ? undefined : json['Title'],
        'body': !exists(json, 'Body') ? undefined : json['Body'],
        'username': !exists(json, 'Username') ? undefined : json['Username'],
        'password': !exists(json, 'Password') ? undefined : json['Password'],
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

export function WebhookIntegrationInfoModelToJSON(value?: WebhookIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'HttpMethodType': value.httpMethodType,
        'ParameterType': value.parameterType,
        'Url': value.url,
        'Issue': value.issue,
        'CustomHttpHeaderModels': value.customHttpHeaderModels === undefined ? undefined : ((value.customHttpHeaderModels as Array<any>).map(CustomHttpHeaderModelToJSON)),
        'Title': value.title,
        'Body': value.body,
        'Username': value.username,
        'Password': value.password,
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

