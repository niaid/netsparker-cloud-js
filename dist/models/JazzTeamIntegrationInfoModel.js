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
exports.JazzTeamIntegrationInfoModelToJSON = exports.JazzTeamIntegrationInfoModelFromJSONTyped = exports.JazzTeamIntegrationInfoModelFromJSON = exports.instanceOfJazzTeamIntegrationInfoModel = exports.JazzTeamIntegrationInfoModelStateEnum = exports.JazzTeamIntegrationInfoModelTypeEnum = exports.JazzTeamIntegrationInfoModelTemplateTypeEnum = exports.JazzTeamIntegrationInfoModelWorkItemTypeEnum = exports.JazzTeamIntegrationInfoModelPriorityEnum = exports.JazzTeamIntegrationInfoModelSeverityEnum = void 0;
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
/**
 * @export
 */
exports.JazzTeamIntegrationInfoModelSeverityEnum = {
    Blocker: 'Blocker',
    Critical: 'Critical',
    Major: 'Major',
    Normal: 'Normal',
    Minor: 'Minor',
    Unclassified: 'Unclassified'
};
/**
 * @export
 */
exports.JazzTeamIntegrationInfoModelPriorityEnum = {
    High: 'High',
    Medium: 'Medium',
    Low: 'Low',
    Unassigned: 'Unassigned'
};
/**
 * @export
 */
exports.JazzTeamIntegrationInfoModelWorkItemTypeEnum = {
    Task: 'Task',
    Defect: 'Defect'
};
/**
 * @export
 */
exports.JazzTeamIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * @export
 */
exports.JazzTeamIntegrationInfoModelTypeEnum = {
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
exports.JazzTeamIntegrationInfoModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
};
/**
 * Check if a given object implements the JazzTeamIntegrationInfoModel interface.
 */
function instanceOfJazzTeamIntegrationInfoModel(value) {
    if (!('serverURL' in value))
        return false;
    if (!('username' in value))
        return false;
    if (!('password' in value))
        return false;
    if (!('projectAreaId' in value))
        return false;
    if (!('categoryName' in value))
        return false;
    if (!('titleFormat' in value))
        return false;
    return true;
}
exports.instanceOfJazzTeamIntegrationInfoModel = instanceOfJazzTeamIntegrationInfoModel;
function JazzTeamIntegrationInfoModelFromJSON(json) {
    return JazzTeamIntegrationInfoModelFromJSONTyped(json, false);
}
exports.JazzTeamIntegrationInfoModelFromJSON = JazzTeamIntegrationInfoModelFromJSON;
function JazzTeamIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'serverURL': json['ServerURL'],
        'username': json['Username'],
        'password': json['Password'],
        'projectAreaId': json['ProjectAreaId'],
        'categoryName': json['CategoryName'],
        'tags': json['Tags'] == null ? undefined : json['Tags'],
        'dueDays': json['DueDays'] == null ? undefined : json['DueDays'],
        'severity': json['Severity'] == null ? undefined : json['Severity'],
        'priority': json['Priority'] == null ? undefined : json['Priority'],
        'workItemType': json['WorkItemType'] == null ? undefined : json['WorkItemType'],
        'templateType': json['TemplateType'] == null ? undefined : json['TemplateType'],
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
        'reopenStatus': json['ReopenStatus'] == null ? undefined : json['ReopenStatus'],
        'resolvedStatus': json['ResolvedStatus'] == null ? undefined : json['ResolvedStatus'],
        'titleFormat': json['TitleFormat'],
        'integrationWizardResultModel': json['IntegrationWizardResultModel'] == null ? undefined : (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelFromJSON)(json['IntegrationWizardResultModel']),
        'id': json['Id'] == null ? undefined : json['Id'],
        'state': json['State'] == null ? undefined : json['State'],
    };
}
exports.JazzTeamIntegrationInfoModelFromJSONTyped = JazzTeamIntegrationInfoModelFromJSONTyped;
function JazzTeamIntegrationInfoModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'ServerURL': value['serverURL'],
        'Username': value['username'],
        'Password': value['password'],
        'ProjectAreaId': value['projectAreaId'],
        'CategoryName': value['categoryName'],
        'Tags': value['tags'],
        'DueDays': value['dueDays'],
        'Severity': value['severity'],
        'Priority': value['priority'],
        'WorkItemType': value['workItemType'],
        'TemplateType': value['templateType'],
        'Name': value['name'],
        'IntegrationVersion': value['integrationVersion'],
        'AccountID': value['accountID'],
        'CustomFields': value['customFields'] == null ? undefined : (value['customFields'].map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmToJSON)),
        'ReopenStatus': value['reopenStatus'],
        'ResolvedStatus': value['resolvedStatus'],
        'TitleFormat': value['titleFormat'],
        'IntegrationWizardResultModel': (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelToJSON)(value['integrationWizardResultModel']),
        'Id': value['id'],
        'State': value['state'],
    };
}
exports.JazzTeamIntegrationInfoModelToJSON = JazzTeamIntegrationInfoModelToJSON;
//# sourceMappingURL=JazzTeamIntegrationInfoModel.js.map