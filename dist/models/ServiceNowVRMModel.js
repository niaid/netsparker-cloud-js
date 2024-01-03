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
import { FieldPairValueFromJSON, FieldPairValueToJSON, } from './FieldPairValue';
import { IntegrationCustomFieldVmFromJSON, IntegrationCustomFieldVmToJSON, } from './IntegrationCustomFieldVm';
import { IntegrationWizardResultModelFromJSON, IntegrationWizardResultModelToJSON, } from './IntegrationWizardResultModel';
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
};
/**
 * @export
 */
export const ServiceNowVRMModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * Check if a given object implements the ServiceNowVRMModel interface.
 */
export function instanceOfServiceNowVRMModel(value) {
    let isInstance = true;
    isInstance = isInstance && "username" in value;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "password" in value;
    isInstance = isInstance && "summaryFormat" in value;
    isInstance = isInstance && "titleFormat" in value;
    return isInstance;
}
export function ServiceNowVRMModelFromJSON(json) {
    return ServiceNowVRMModelFromJSONTyped(json, false);
}
export function ServiceNowVRMModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'username': json['Username'],
        'url': json['Url'],
        'webhookUrl': !exists(json, 'WebhookUrl') ? undefined : json['WebhookUrl'],
        'password': json['Password'],
        'fieldPairs': !exists(json, 'FieldPairs') ? undefined : (mapValues(json['FieldPairs'], FieldPairValueFromJSON)),
        'resolvedStatus': !exists(json, 'ResolvedStatus') ? undefined : json['ResolvedStatus'],
        'reopenStatus': !exists(json, 'ReopenStatus') ? undefined : json['ReopenStatus'],
        'falsePositiveStatus': !exists(json, 'FalsePositiveStatus') ? undefined : json['FalsePositiveStatus'],
        'acceptedRiskStatus': !exists(json, 'AcceptedRiskStatus') ? undefined : json['AcceptedRiskStatus'],
        'summaryFormat': json['SummaryFormat'],
        'cIMatchingColumn': !exists(json, 'CIMatchingColumn') ? undefined : json['CIMatchingColumn'],
        'cIMatchingColumnText': !exists(json, 'CIMatchingColumnText') ? undefined : json['CIMatchingColumnText'],
        'type': !exists(json, 'Type') ? undefined : json['Type'],
        'genericErrorMessage': !exists(json, 'GenericErrorMessage') ? undefined : json['GenericErrorMessage'],
        'identifier': !exists(json, 'Identifier') ? undefined : json['Identifier'],
        'testMessageBody': !exists(json, 'TestMessageBody') ? undefined : json['TestMessageBody'],
        'testMessageTitle': !exists(json, 'TestMessageTitle') ? undefined : json['TestMessageTitle'],
        'name': !exists(json, 'Name') ? undefined : json['Name'],
        'integrationVersion': !exists(json, 'IntegrationVersion') ? undefined : json['IntegrationVersion'],
        'accountID': !exists(json, 'AccountID') ? undefined : json['AccountID'],
        'customFields': !exists(json, 'CustomFields') ? undefined : (json['CustomFields'].map(IntegrationCustomFieldVmFromJSON)),
        'templateType': !exists(json, 'TemplateType') ? undefined : json['TemplateType'],
        'titleFormat': json['TitleFormat'],
        'integrationWizardResultModel': !exists(json, 'IntegrationWizardResultModel') ? undefined : IntegrationWizardResultModelFromJSON(json['IntegrationWizardResultModel']),
    };
}
export function ServiceNowVRMModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Username': value.username,
        'Url': value.url,
        'Password': value.password,
        'FieldPairs': value.fieldPairs === undefined ? undefined : (mapValues(value.fieldPairs, FieldPairValueToJSON)),
        'SummaryFormat': value.summaryFormat,
        'CIMatchingColumn': value.cIMatchingColumn,
        'CIMatchingColumnText': value.cIMatchingColumnText,
        'Name': value.name,
        'IntegrationVersion': value.integrationVersion,
        'AccountID': value.accountID,
        'CustomFields': value.customFields === undefined ? undefined : (value.customFields.map(IntegrationCustomFieldVmToJSON)),
        'TemplateType': value.templateType,
        'TitleFormat': value.titleFormat,
        'IntegrationWizardResultModel': IntegrationWizardResultModelToJSON(value.integrationWizardResultModel),
    };
}
//# sourceMappingURL=ServiceNowVRMModel.js.map