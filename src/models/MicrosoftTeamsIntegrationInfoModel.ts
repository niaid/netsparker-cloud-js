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
 * The Microsoft Teams integration info
 * @export
 * @interface MicrosoftTeamsIntegrationInfoModel
 */
export interface MicrosoftTeamsIntegrationInfoModel {
    /**
     * Gets or sets the Webhook URL.
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    webhookUrl: string;
    /**
     * Gets or sets the Color.
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    color?: string;
    /**
     * 
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    readonly type?: MicrosoftTeamsIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    templateType?: MicrosoftTeamsIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof MicrosoftTeamsIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}

/**
* @export
* @enum {string}
*/
export enum MicrosoftTeamsIntegrationInfoModelTypeEnum {
    NetsparkerEnterprise = 'NetsparkerEnterprise',
    Webhook = 'Webhook',
    Zapier = 'Zapier',
    Slack = 'Slack',
    Mattermost = 'Mattermost',
    MicrosoftTeams = 'MicrosoftTeams',
    AzureDevOps = 'AzureDevOps',
    Bitbucket = 'Bitbucket',
    Bugzilla = 'Bugzilla',
    Clubhouse = 'Clubhouse',
    DefectDojo = 'DefectDojo',
    PivotalTracker = 'PivotalTracker',
    Jira = 'Jira',
    FogBugz = 'FogBugz',
    GitHub = 'GitHub',
    PagerDuty = 'PagerDuty',
    Kafka = 'Kafka',
    Kenna = 'Kenna',
    Redmine = 'Redmine',
    ServiceNow = 'ServiceNow',
    Tfs = 'TFS',
    Unfuddle = 'Unfuddle',
    YouTrack = 'YouTrack',
    Freshservice = 'Freshservice',
    Splunk = 'Splunk',
    JazzTeam = 'JazzTeam',
    ServiceNowVrm = 'ServiceNowVRM',
    Asana = 'Asana',
    Trello = 'Trello',
    Hashicorp = 'Hashicorp',
    CyberArk = 'CyberArk',
    AzureKeyVault = 'AzureKeyVault',
    GitLab = 'GitLab'
}
/**
* @export
* @enum {string}
*/
export enum MicrosoftTeamsIntegrationInfoModelTemplateTypeEnum {
    Standard = 'Standard',
    Detailed = 'Detailed'
}


/**
 * Check if a given object implements the MicrosoftTeamsIntegrationInfoModel interface.
 */
export function instanceOfMicrosoftTeamsIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "webhookUrl" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function MicrosoftTeamsIntegrationInfoModelFromJSON(json: any): MicrosoftTeamsIntegrationInfoModel {
    return MicrosoftTeamsIntegrationInfoModelFromJSONTyped(json, false);
}

export function MicrosoftTeamsIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): MicrosoftTeamsIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'webhookUrl': json['WebhookUrl'],
        'color': !exists(json, 'Color') ? undefined : json['Color'],
        'type': !exists(json, 'Type') ? undefined : json['Type'],
        'genericErrorMessage': !exists(json, 'GenericErrorMessage') ? undefined : json['GenericErrorMessage'],
        'identifier': !exists(json, 'Identifier') ? undefined : json['Identifier'],
        'testMessageBody': !exists(json, 'TestMessageBody') ? undefined : json['TestMessageBody'],
        'testMessageTitle': !exists(json, 'TestMessageTitle') ? undefined : json['TestMessageTitle'],
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

export function MicrosoftTeamsIntegrationInfoModelToJSON(value?: MicrosoftTeamsIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'WebhookUrl': value.webhookUrl,
        'Color': value.color,
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

