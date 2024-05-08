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
import type { FieldPairValue } from './FieldPairValue';
import {
    FieldPairValueFromJSON,
    FieldPairValueFromJSONTyped,
    FieldPairValueToJSON,
} from './FieldPairValue';
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
 * 
 * @export
 * @interface ServiceNowVRMModel
 */
export interface ServiceNowVRMModel {
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    username: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    url: string;
    /**
     * Gets web hook URL.
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly webhookUrl?: string;
    /**
     * Gets or sets the ServiceNow password for the user.
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    password: string;
    /**
     * 
     * @type {{ [key: string]: FieldPairValue; }}
     * @memberof ServiceNowVRMModel
     */
    fieldPairs?: { [key: string]: FieldPairValue; };
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly falsePositiveStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly acceptedRiskStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    summaryFormat: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    cIMatchingColumn?: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    cIMatchingColumnText?: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly type?: ServiceNowVRMModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof ServiceNowVRMModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof ServiceNowVRMModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    templateType?: ServiceNowVRMModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof ServiceNowVRMModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    id?: string;
    /**
     * 
     * @type {string}
     * @memberof ServiceNowVRMModel
     */
    state?: ServiceNowVRMModelStateEnum;
}


/**
 * @export
 */
export const ServiceNowVRMModelTypeEnum = {
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
export type ServiceNowVRMModelTypeEnum = typeof ServiceNowVRMModelTypeEnum[keyof typeof ServiceNowVRMModelTypeEnum];

/**
 * @export
 */
export const ServiceNowVRMModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type ServiceNowVRMModelTemplateTypeEnum = typeof ServiceNowVRMModelTemplateTypeEnum[keyof typeof ServiceNowVRMModelTemplateTypeEnum];

/**
 * @export
 */
export const ServiceNowVRMModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
} as const;
export type ServiceNowVRMModelStateEnum = typeof ServiceNowVRMModelStateEnum[keyof typeof ServiceNowVRMModelStateEnum];


/**
 * Check if a given object implements the ServiceNowVRMModel interface.
 */
export function instanceOfServiceNowVRMModel(value: object): boolean {
    if (!('username' in value)) return false;
    if (!('url' in value)) return false;
    if (!('password' in value)) return false;
    if (!('summaryFormat' in value)) return false;
    if (!('titleFormat' in value)) return false;
    return true;
}

export function ServiceNowVRMModelFromJSON(json: any): ServiceNowVRMModel {
    return ServiceNowVRMModelFromJSONTyped(json, false);
}

export function ServiceNowVRMModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ServiceNowVRMModel {
    if (json == null) {
        return json;
    }
    return {
        
        'username': json['Username'],
        'url': json['Url'],
        'webhookUrl': json['WebhookUrl'] == null ? undefined : json['WebhookUrl'],
        'password': json['Password'],
        'fieldPairs': json['FieldPairs'] == null ? undefined : (mapValues(json['FieldPairs'], FieldPairValueFromJSON)),
        'resolvedStatus': json['ResolvedStatus'] == null ? undefined : json['ResolvedStatus'],
        'reopenStatus': json['ReopenStatus'] == null ? undefined : json['ReopenStatus'],
        'falsePositiveStatus': json['FalsePositiveStatus'] == null ? undefined : json['FalsePositiveStatus'],
        'acceptedRiskStatus': json['AcceptedRiskStatus'] == null ? undefined : json['AcceptedRiskStatus'],
        'summaryFormat': json['SummaryFormat'],
        'cIMatchingColumn': json['CIMatchingColumn'] == null ? undefined : json['CIMatchingColumn'],
        'cIMatchingColumnText': json['CIMatchingColumnText'] == null ? undefined : json['CIMatchingColumnText'],
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
        'titleFormat': json['TitleFormat'],
        'integrationWizardResultModel': json['IntegrationWizardResultModel'] == null ? undefined : IntegrationWizardResultModelFromJSON(json['IntegrationWizardResultModel']),
        'id': json['Id'] == null ? undefined : json['Id'],
        'state': json['State'] == null ? undefined : json['State'],
    };
}

export function ServiceNowVRMModelToJSON(value?: Omit<ServiceNowVRMModel, 'WebhookUrl'|'ResolvedStatus'|'ReopenStatus'|'FalsePositiveStatus'|'AcceptedRiskStatus'|'Type'|'GenericErrorMessage'|'Identifier'|'TestMessageBody'|'TestMessageTitle'> | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Username': value['username'],
        'Url': value['url'],
        'Password': value['password'],
        'FieldPairs': value['fieldPairs'] == null ? undefined : (mapValues(value['fieldPairs'], FieldPairValueToJSON)),
        'SummaryFormat': value['summaryFormat'],
        'CIMatchingColumn': value['cIMatchingColumn'],
        'CIMatchingColumnText': value['cIMatchingColumnText'],
        'Name': value['name'],
        'IntegrationVersion': value['integrationVersion'],
        'AccountID': value['accountID'],
        'CustomFields': value['customFields'] == null ? undefined : ((value['customFields'] as Array<any>).map(IntegrationCustomFieldVmToJSON)),
        'TemplateType': value['templateType'],
        'TitleFormat': value['titleFormat'],
        'IntegrationWizardResultModel': IntegrationWizardResultModelToJSON(value['integrationWizardResultModel']),
        'Id': value['id'],
        'State': value['state'],
    };
}

