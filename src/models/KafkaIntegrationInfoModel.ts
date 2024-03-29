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
 * The Kafka integration info
 * @export
 * @interface KafkaIntegrationInfoModel
 */
export interface KafkaIntegrationInfoModel {
    /**
     * Gets or sets the access token.
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    topic: string;
    /**
     * Gets or sets the serialization type
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    dataSerialization: KafkaIntegrationInfoModelDataSerializationEnum;
    /**
     * Gets or sets the schema registry url.
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    schemaRegistryUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    readonly type?: KafkaIntegrationInfoModelTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    readonly genericErrorMessage?: string;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    readonly identifier?: string;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    readonly testMessageBody?: string;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    readonly testMessageTitle?: string;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    readonly webhookUrl?: string;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    name?: string;
    /**
     * 
     * @type {number}
     * @memberof KafkaIntegrationInfoModel
     */
    integrationVersion?: number;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    accountID?: string;
    /**
     * 
     * @type {Array<IntegrationCustomFieldVm>}
     * @memberof KafkaIntegrationInfoModel
     */
    customFields?: Array<IntegrationCustomFieldVm>;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    templateType?: KafkaIntegrationInfoModelTemplateTypeEnum;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    reopenStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    resolvedStatus?: string;
    /**
     * 
     * @type {string}
     * @memberof KafkaIntegrationInfoModel
     */
    titleFormat: string;
    /**
     * 
     * @type {IntegrationWizardResultModel}
     * @memberof KafkaIntegrationInfoModel
     */
    integrationWizardResultModel?: IntegrationWizardResultModel;
}


/**
 * @export
 */
export const KafkaIntegrationInfoModelDataSerializationEnum = {
    JsonSerialized: 'JsonSerialized',
    FlattenedJsonSerialized: 'FlattenedJsonSerialized',
    AvroSerialized: 'AvroSerialized'
} as const;
export type KafkaIntegrationInfoModelDataSerializationEnum = typeof KafkaIntegrationInfoModelDataSerializationEnum[keyof typeof KafkaIntegrationInfoModelDataSerializationEnum];

/**
 * @export
 */
export const KafkaIntegrationInfoModelTypeEnum = {
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
export type KafkaIntegrationInfoModelTypeEnum = typeof KafkaIntegrationInfoModelTypeEnum[keyof typeof KafkaIntegrationInfoModelTypeEnum];

/**
 * @export
 */
export const KafkaIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
} as const;
export type KafkaIntegrationInfoModelTemplateTypeEnum = typeof KafkaIntegrationInfoModelTemplateTypeEnum[keyof typeof KafkaIntegrationInfoModelTemplateTypeEnum];


/**
 * Check if a given object implements the KafkaIntegrationInfoModel interface.
 */
export function instanceOfKafkaIntegrationInfoModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "topic" in value;
    isInstance = isInstance && "dataSerialization" in value;
    isInstance = isInstance && "titleFormat" in value;

    return isInstance;
}

export function KafkaIntegrationInfoModelFromJSON(json: any): KafkaIntegrationInfoModel {
    return KafkaIntegrationInfoModelFromJSONTyped(json, false);
}

export function KafkaIntegrationInfoModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): KafkaIntegrationInfoModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'topic': json['Topic'],
        'dataSerialization': json['DataSerialization'],
        'schemaRegistryUrl': !exists(json, 'SchemaRegistryUrl') ? undefined : json['SchemaRegistryUrl'],
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

export function KafkaIntegrationInfoModelToJSON(value?: KafkaIntegrationInfoModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Topic': value.topic,
        'DataSerialization': value.dataSerialization,
        'SchemaRegistryUrl': value.schemaRegistryUrl,
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

