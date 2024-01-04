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
exports.RedmineIntegrationInfoModelToJSON = exports.RedmineIntegrationInfoModelFromJSONTyped = exports.RedmineIntegrationInfoModelFromJSON = exports.instanceOfRedmineIntegrationInfoModel = exports.RedmineIntegrationInfoModelTemplateTypeEnum = exports.RedmineIntegrationInfoModelTypeEnum = void 0;
const runtime_1 = require("../runtime");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
/**
 * @export
 */
exports.RedmineIntegrationInfoModelTypeEnum = {
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
};
/**
 * @export
 */
exports.RedmineIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * Check if a given object implements the RedmineIntegrationInfoModel interface.
 */
function instanceOfRedmineIntegrationInfoModel(value) {
    let isInstance = true;
    isInstance = isInstance && "url" in value;
    isInstance = isInstance && "apiAccessKey" in value;
    isInstance = isInstance && "project" in value;
    isInstance = isInstance && "priorityId" in value;
    isInstance = isInstance && "titleFormat" in value;
    return isInstance;
}
exports.instanceOfRedmineIntegrationInfoModel = instanceOfRedmineIntegrationInfoModel;
function RedmineIntegrationInfoModelFromJSON(json) {
    return RedmineIntegrationInfoModelFromJSONTyped(json, false);
}
exports.RedmineIntegrationInfoModelFromJSON = RedmineIntegrationInfoModelFromJSON;
function RedmineIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'url': json['Url'],
        'apiAccessKey': json['ApiAccessKey'],
        'project': json['Project'],
        'priorityId': json['PriorityId'],
        'trackerId': !(0, runtime_1.exists)(json, 'TrackerId') ? undefined : json['TrackerId'],
        'statusId': !(0, runtime_1.exists)(json, 'StatusId') ? undefined : json['StatusId'],
        'categoryId': !(0, runtime_1.exists)(json, 'CategoryId') ? undefined : json['CategoryId'],
        'assignedTo': !(0, runtime_1.exists)(json, 'AssignedTo') ? undefined : json['AssignedTo'],
        'dueDays': !(0, runtime_1.exists)(json, 'DueDays') ? undefined : json['DueDays'],
        'isPrivate': !(0, runtime_1.exists)(json, 'IsPrivate') ? undefined : json['IsPrivate'],
        'type': !(0, runtime_1.exists)(json, 'Type') ? undefined : json['Type'],
        'genericErrorMessage': !(0, runtime_1.exists)(json, 'GenericErrorMessage') ? undefined : json['GenericErrorMessage'],
        'identifier': !(0, runtime_1.exists)(json, 'Identifier') ? undefined : json['Identifier'],
        'testMessageBody': !(0, runtime_1.exists)(json, 'TestMessageBody') ? undefined : json['TestMessageBody'],
        'testMessageTitle': !(0, runtime_1.exists)(json, 'TestMessageTitle') ? undefined : json['TestMessageTitle'],
        'webhookUrl': !(0, runtime_1.exists)(json, 'WebhookUrl') ? undefined : json['WebhookUrl'],
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
exports.RedmineIntegrationInfoModelFromJSONTyped = RedmineIntegrationInfoModelFromJSONTyped;
function RedmineIntegrationInfoModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Url': value.url,
        'ApiAccessKey': value.apiAccessKey,
        'Project': value.project,
        'PriorityId': value.priorityId,
        'TrackerId': value.trackerId,
        'StatusId': value.statusId,
        'CategoryId': value.categoryId,
        'AssignedTo': value.assignedTo,
        'DueDays': value.dueDays,
        'IsPrivate': value.isPrivate,
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
exports.RedmineIntegrationInfoModelToJSON = RedmineIntegrationInfoModelToJSON;
//# sourceMappingURL=RedmineIntegrationInfoModel.js.map