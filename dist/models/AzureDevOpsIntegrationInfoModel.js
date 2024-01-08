"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AzureDevOpsIntegrationInfoModelToJSON = exports.AzureDevOpsIntegrationInfoModelFromJSONTyped = exports.AzureDevOpsIntegrationInfoModelFromJSON = exports.instanceOfAzureDevOpsIntegrationInfoModel = exports.AzureDevOpsIntegrationInfoModelTemplateTypeEnum = exports.AzureDevOpsIntegrationInfoModelTypeEnum = void 0;
const runtime_1 = require("../runtime");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
/**
 * @export
 */
exports.AzureDevOpsIntegrationInfoModelTypeEnum = {
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
exports.AzureDevOpsIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * Check if a given object implements the AzureDevOpsIntegrationInfoModel interface.
 */
function instanceOfAzureDevOpsIntegrationInfoModel(value) {
    let isInstance = true;
    isInstance = isInstance && "password" in value;
    isInstance = isInstance && "projectUri" in value;
    isInstance = isInstance && "workItemTypeName" in value;
    isInstance = isInstance && "titleFormat" in value;
    return isInstance;
}
exports.instanceOfAzureDevOpsIntegrationInfoModel = instanceOfAzureDevOpsIntegrationInfoModel;
function AzureDevOpsIntegrationInfoModelFromJSON(json) {
    return AzureDevOpsIntegrationInfoModelFromJSONTyped(json, false);
}
exports.AzureDevOpsIntegrationInfoModelFromJSON = AzureDevOpsIntegrationInfoModelFromJSON;
function AzureDevOpsIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'password': json['Password'],
        'username': !(0, runtime_1.exists)(json, 'Username') ? undefined : json['Username'],
        'assignedTo': !(0, runtime_1.exists)(json, 'AssignedTo') ? undefined : json['AssignedTo'],
        'domain': !(0, runtime_1.exists)(json, 'Domain') ? undefined : json['Domain'],
        'projectUri': json['ProjectUri'],
        'tags': !(0, runtime_1.exists)(json, 'Tags') ? undefined : json['Tags'],
        'workItemTypeName': json['WorkItemTypeName'],
        'webhookUrl': !(0, runtime_1.exists)(json, 'WebhookUrl') ? undefined : json['WebhookUrl'],
        'type': !(0, runtime_1.exists)(json, 'Type') ? undefined : json['Type'],
        'genericErrorMessage': !(0, runtime_1.exists)(json, 'GenericErrorMessage') ? undefined : json['GenericErrorMessage'],
        'identifier': !(0, runtime_1.exists)(json, 'Identifier') ? undefined : json['Identifier'],
        'testMessageBody': !(0, runtime_1.exists)(json, 'TestMessageBody') ? undefined : json['TestMessageBody'],
        'testMessageTitle': !(0, runtime_1.exists)(json, 'TestMessageTitle') ? undefined : json['TestMessageTitle'],
        'name': !(0, runtime_1.exists)(json, 'Name') ? undefined : json['Name'],
        'integrationVersion': !(0, runtime_1.exists)(json, 'IntegrationVersion') ? undefined : json['IntegrationVersion'],
        'accountID': !(0, runtime_1.exists)(json, 'AccountID') ? undefined : json['AccountID'],
        'customFields': !(0, runtime_1.exists)(json, 'CustomFields') ? undefined : (json['CustomFields'].map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmFromJSON)),
        'templateType': !(0, runtime_1.exists)(json, 'TemplateType') ? undefined : json['TemplateType'],
        'reopenStatus': !(0, runtime_1.exists)(json, 'ReopenStatus') ? undefined : json['ReopenStatus'],
        'resolvedStatus': !(0, runtime_1.exists)(json, 'ResolvedStatus') ? undefined : json['ResolvedStatus'],
        'titleFormat': json['TitleFormat'],
        'integrationWizardResultModel': !(0, runtime_1.exists)(json, 'IntegrationWizardResultModel') ? undefined : (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelFromJSON)(json['IntegrationWizardResultModel']),
    };
}
exports.AzureDevOpsIntegrationInfoModelFromJSONTyped = AzureDevOpsIntegrationInfoModelFromJSONTyped;
function AzureDevOpsIntegrationInfoModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Password': value.password,
        'Username': value.username,
        'AssignedTo': value.assignedTo,
        'Domain': value.domain,
        'ProjectUri': value.projectUri,
        'Tags': value.tags,
        'WorkItemTypeName': value.workItemTypeName,
        'Name': value.name,
        'IntegrationVersion': value.integrationVersion,
        'AccountID': value.accountID,
        'CustomFields': value.customFields === undefined ? undefined : (value.customFields.map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmToJSON)),
        'TemplateType': value.templateType,
        'ReopenStatus': value.reopenStatus,
        'ResolvedStatus': value.resolvedStatus,
        'TitleFormat': value.titleFormat,
        'IntegrationWizardResultModel': (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelToJSON)(value.integrationWizardResultModel),
    };
}
exports.AzureDevOpsIntegrationInfoModelToJSON = AzureDevOpsIntegrationInfoModelToJSON;
//# sourceMappingURL=AzureDevOpsIntegrationInfoModel.js.map