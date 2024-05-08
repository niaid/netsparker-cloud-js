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
exports.UnfuddleIntegrationInfoModelToJSON = exports.UnfuddleIntegrationInfoModelFromJSONTyped = exports.UnfuddleIntegrationInfoModelFromJSON = exports.instanceOfUnfuddleIntegrationInfoModel = exports.UnfuddleIntegrationInfoModelStateEnum = exports.UnfuddleIntegrationInfoModelTemplateTypeEnum = exports.UnfuddleIntegrationInfoModelTypeEnum = void 0;
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
/**
 * @export
 */
exports.UnfuddleIntegrationInfoModelTypeEnum = {
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
exports.UnfuddleIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * @export
 */
exports.UnfuddleIntegrationInfoModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
};
/**
 * Check if a given object implements the UnfuddleIntegrationInfoModel interface.
 */
function instanceOfUnfuddleIntegrationInfoModel(value) {
    if (!('password' in value))
        return false;
    if (!('priority' in value))
        return false;
    if (!('projectId' in value))
        return false;
    if (!('subdomain' in value))
        return false;
    if (!('username' in value))
        return false;
    if (!('titleFormat' in value))
        return false;
    return true;
}
exports.instanceOfUnfuddleIntegrationInfoModel = instanceOfUnfuddleIntegrationInfoModel;
function UnfuddleIntegrationInfoModelFromJSON(json) {
    return UnfuddleIntegrationInfoModelFromJSONTyped(json, false);
}
exports.UnfuddleIntegrationInfoModelFromJSON = UnfuddleIntegrationInfoModelFromJSON;
function UnfuddleIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'assigneeId': json['AssigneeId'] == null ? undefined : json['AssigneeId'],
        'dueDays': json['DueDays'] == null ? undefined : json['DueDays'],
        'milestoneId': json['MilestoneId'] == null ? undefined : json['MilestoneId'],
        'password': json['Password'],
        'priority': json['Priority'],
        'projectId': json['ProjectId'],
        'subdomain': json['Subdomain'],
        'username': json['Username'],
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
exports.UnfuddleIntegrationInfoModelFromJSONTyped = UnfuddleIntegrationInfoModelFromJSONTyped;
function UnfuddleIntegrationInfoModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'AssigneeId': value['assigneeId'],
        'DueDays': value['dueDays'],
        'MilestoneId': value['milestoneId'],
        'Password': value['password'],
        'Priority': value['priority'],
        'ProjectId': value['projectId'],
        'Subdomain': value['subdomain'],
        'Username': value['username'],
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
exports.UnfuddleIntegrationInfoModelToJSON = UnfuddleIntegrationInfoModelToJSON;
//# sourceMappingURL=UnfuddleIntegrationInfoModel.js.map