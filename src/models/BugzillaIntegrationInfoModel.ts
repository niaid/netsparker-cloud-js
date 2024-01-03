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
 * The Bugzilla integration info
 * @export
 * @interface BugzillaIntegrationInfoModel
 */
export interface BugzillaIntegrationInfoModel {
    /**
     * The Bugzilla instance URL.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    url: string;
    /**
     * API Key for authentication.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    apiKey: string;
    /**
     * The product name.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    product: string;
    /**
     * The name of a component.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    component: string;
    /**
     * The product version that the issue was found in.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    version: string;
    /**
     * What type of hardware the bug was experienced on.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    platform: string;
    /**
     * The operating system the bug was discovered on.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    operationSystem: string;
    /**
     * The status that this bug should start out as.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    status?: string;
    /**
     * The priority of the bug.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    priority?: string;
    /**
     * The user email adress to assign issues to.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    assignedTo?: string;
    /**
     * The serverity of the bug.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    severity?: string;
    /**
     * A valid target milestone for the product.
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    milestone?: string;
    /**
     * The days when incident is due from the time that issue is created on.
     * @type {number}
     * @memberof BugzillaIntegrationInfoModel
     */
    dueDays?: number;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly type?: BugzillaIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof BugzillaIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof BugzillaIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    templateType?: BugzillaIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof BugzillaIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof BugzillaIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}


/**
 * @export
 */
export const BugzillaIntegrationInfoModelTypeEnum = {
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
export type BugzillaIntegrationInfoModelTypeEnum = typeof BugzillaIntegrationInfoModelTypeEnum[keyof typeof BugzillaIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const BugzillaIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type BugzillaIntegrationInfoModelTemplateTypeEnum = typeof BugzillaIntegrationInfoModelTemplateTypeEnum[keyof typeof BugzillaIntegrationInfoModelTemplateTypeEnum];


/**
 * Check if a given object implements the BugzillaIntegrationInfoModel interface.
 */
export function instanceOfBugzillaIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "apiKey" in value;
    isInstance = isInstance && "product" in value;
    isInstance = isInstance && "component" in value;
    isInstance = isInstance && "version" in value;
    isInstance = isInstance && "platform" in value;
    isInstance = isInstance && "operationSystem" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function BugzillaIntegrationInfoModelFromJSON(json: any): BugzillaIntegrationInfoModel {
    return BugzillaIntegrationInfoModelFromJSONTyped(json, false);
}

export function BugzillaIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): BugzillaIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'url': json['Url'],
        'apiKey': json['ApiKey'],
        'product': json['Product'],
        'component': json['Component'],
        'version': json['Version'],
        'platform': json['Platform'],
        'operationSystem': json['OperationSystem'],
        'status': !exists(json, 'Status') ? undefined : json['Status'],
        'priority': !exists(json, 'Priority') ? undefined : json['Priority'],
        'assignedTo': !exists(json, 'AssignedTo') ? undefined : json['AssignedTo'],
        'severity': !exists(json, 'Severity') ? undefined : json['Severity'],
        'milestone': !exists(json, 'Milestone') ? undefined : json['Milestone'],
        'dueDays': !exists(json, 'DueDays') ? undefined : json['DueDays'],
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

export function BugzillaIntegrationInfoModelToJSON(value?: BugzillaIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Url': value.url,
        'ApiKey': value.apiKey,
        'Product': value.product,
        'Component': value.component,
        'Version': value.version,
        'Platform': value.platform,
        'OperationSystem': value.operationSystem,
        'Status': value.status,
        'Priority': value.priority,
        'AssignedTo': value.assignedTo,
        'Severity': value.severity,
        'Milestone': value.milestone,
        'DueDays': value.dueDays,
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

