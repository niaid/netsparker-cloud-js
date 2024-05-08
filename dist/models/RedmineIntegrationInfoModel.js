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
exports.RedmineIntegrationInfoModelToJSON = exports.RedmineIntegrationInfoModelFromJSONTyped = exports.RedmineIntegrationInfoModelFromJSON = exports.instanceOfRedmineIntegrationInfoModel = exports.RedmineIntegrationInfoModelStateEnum = exports.RedmineIntegrationInfoModelTemplateTypeEnum = exports.RedmineIntegrationInfoModelTypeEnum = void 0;
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
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
 * @export
 */
exports.RedmineIntegrationInfoModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
};
/**
 * Check if a given object implements the RedmineIntegrationInfoModel interface.
 */
function instanceOfRedmineIntegrationInfoModel(value) {
    if (!('url' in value))
        return false;
    if (!('apiAccessKey' in value))
        return false;
    if (!('project' in value))
        return false;
    if (!('priorityId' in value))
        return false;
    if (!('titleFormat' in value))
        return false;
    return true;
}
exports.instanceOfRedmineIntegrationInfoModel = instanceOfRedmineIntegrationInfoModel;
function RedmineIntegrationInfoModelFromJSON(json) {
    return RedmineIntegrationInfoModelFromJSONTyped(json, false);
}
exports.RedmineIntegrationInfoModelFromJSON = RedmineIntegrationInfoModelFromJSON;
function RedmineIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'url': json['Url'],
        'apiAccessKey': json['ApiAccessKey'],
        'project': json['Project'],
        'priorityId': json['PriorityId'],
        'trackerId': json['TrackerId'] == null ? undefined : json['TrackerId'],
        'statusId': json['StatusId'] == null ? undefined : json['StatusId'],
        'categoryId': json['CategoryId'] == null ? undefined : json['CategoryId'],
        'assignedTo': json['AssignedTo'] == null ? undefined : json['AssignedTo'],
        'dueDays': json['DueDays'] == null ? undefined : json['DueDays'],
        'isPrivate': json['IsPrivate'] == null ? undefined : json['IsPrivate'],
        'type': json['Type'] == null ? undefined : json['Type'],
        'genericErrorMessage': json['GenericErrorMessage'] == null ? undefined : json['GenericErrorMessage'],
        'identifier': json['Identifier'] == null ? undefined : json['Identifier'],
        'testMessageBody': json['TestMessageBody'] == null ? undefined : json['TestMessageBody'],
        'testMessageTitle': json['TestMessageTitle'] == null ? undefined : json['TestMessageTitle'],
        'webhookUrl': json['WebhookUrl'] == null ? undefined : json['WebhookUrl'],
        'name': json['Name'] == null ? undefined : json['Name'],
        'integrationVersion': json['IntegrationVersion'] == null ? undefined : json['IntegrationVersion'],
        'accountID': json['AccountID'] == null ? undefined : json['AccountID'],
        'customFields': json['CustomFields'] == null ? undefined : (json['CustomFields'].map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmFromJSON)),
        'templateType': json['TemplateType'] == null ? undefined : json['TemplateType'],
        'reopenStatus': json['ReopenStatus'] == null ? undefined : json['ReopenStatus'],
        'resolvedStatus': json['ResolvedStatus'] == null ? undefined : json['ResolvedStatus'],
        'titleFormat': json['TitleFormat'],
        'integrationWizardResultModel': json['IntegrationWizardResultModel'] == null ? undefined : (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelFromJSON)(json['IntegrationWizardResultModel']),
        'id': json['Id'] == null ? undefined : json['Id'],
        'state': json['State'] == null ? undefined : json['State'],
    };
}
exports.RedmineIntegrationInfoModelFromJSONTyped = RedmineIntegrationInfoModelFromJSONTyped;
function RedmineIntegrationInfoModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Url': value['url'],
        'ApiAccessKey': value['apiAccessKey'],
        'Project': value['project'],
        'PriorityId': value['priorityId'],
        'TrackerId': value['trackerId'],
        'StatusId': value['statusId'],
        'CategoryId': value['categoryId'],
        'AssignedTo': value['assignedTo'],
        'DueDays': value['dueDays'],
        'IsPrivate': value['isPrivate'],
        'Name': value['name'],
        'IntegrationVersion': value['integrationVersion'],
        'AccountID': value['accountID'],
        'CustomFields': value['customFields'] == null ? undefined : (value['customFields'].map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmToJSON)),
        'TemplateType': value['templateType'],
        'ReopenStatus': value['reopenStatus'],
        'ResolvedStatus': value['resolvedStatus'],
        'TitleFormat': value['titleFormat'],
        'IntegrationWizardResultModel': (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelToJSON)(value['integrationWizardResultModel']),
        'Id': value['id'],
        'State': value['state'],
    };
}
exports.RedmineIntegrationInfoModelToJSON = RedmineIntegrationInfoModelToJSON;
//# sourceMappingURL=RedmineIntegrationInfoModel.js.map