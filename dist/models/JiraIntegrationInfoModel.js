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
exports.JiraIntegrationInfoModelToJSON = exports.JiraIntegrationInfoModelFromJSONTyped = exports.JiraIntegrationInfoModelFromJSON = exports.instanceOfJiraIntegrationInfoModel = exports.JiraIntegrationInfoModelStateEnum = exports.JiraIntegrationInfoModelTypeEnum = exports.JiraIntegrationInfoModelEpicSelectionTypeEnum = exports.JiraIntegrationInfoModelTemplateTypeEnum = exports.JiraIntegrationInfoModelReopenStatusJiraEnum = void 0;
const JiraPriorityMapping_1 = require("./JiraPriorityMapping");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const IntegrationUserMappingItemModel_1 = require("./IntegrationUserMappingItemModel");
/**
 * @export
 */
exports.JiraIntegrationInfoModelReopenStatusJiraEnum = {
    ToDo: 'ToDo',
    InProgress: 'InProgress'
};
/**
 * @export
 */
exports.JiraIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * @export
 */
exports.JiraIntegrationInfoModelEpicSelectionTypeEnum = {
    None: 'None',
    EpicName: 'EpicName',
    EpicKey: 'EpicKey'
};
/**
 * @export
 */
exports.JiraIntegrationInfoModelTypeEnum = {
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
exports.JiraIntegrationInfoModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
};
/**
 * Check if a given object implements the JiraIntegrationInfoModel interface.
 */
function instanceOfJiraIntegrationInfoModel(value) {
    if (!('issueType' in value))
        return false;
    if (!('password' in value))
        return false;
    if (!('projectKey' in value))
        return false;
    if (!('url' in value))
        return false;
    if (!('usernameOrEmail' in value))
        return false;
    if (!('titleFormat' in value))
        return false;
    return true;
}
exports.instanceOfJiraIntegrationInfoModel = instanceOfJiraIntegrationInfoModel;
function JiraIntegrationInfoModelFromJSON(json) {
    return JiraIntegrationInfoModelFromJSONTyped(json, false);
}
exports.JiraIntegrationInfoModelFromJSON = JiraIntegrationInfoModelFromJSON;
function JiraIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'assignedTo': json['AssignedTo'] == null ? undefined : json['AssignedTo'],
        'assignedToName': json['AssignedToName'] == null ? undefined : json['AssignedToName'],
        'autoAssignToPerson': json['AutoAssignToPerson'] == null ? undefined : json['AutoAssignToPerson'],
        'dueDays': json['DueDays'] == null ? undefined : json['DueDays'],
        'isCloud': json['IsCloud'] == null ? undefined : json['IsCloud'],
        'issueType': json['IssueType'],
        'issueTypeId': json['IssueTypeId'] == null ? undefined : json['IssueTypeId'],
        'labels': json['Labels'] == null ? undefined : json['Labels'],
        'components': json['Components'] == null ? undefined : json['Components'],
        'mappedJiraUsers': json['MappedJiraUsers'] == null ? undefined : (json['MappedJiraUsers'].map(IntegrationUserMappingItemModel_1.IntegrationUserMappingItemModelFromJSON)),
        'password': json['Password'],
        'priority': json['Priority'] == null ? undefined : json['Priority'],
        'securityLevel': json['SecurityLevel'] == null ? undefined : json['SecurityLevel'],
        'projectKey': json['ProjectKey'],
        'projectName': json['ProjectName'] == null ? undefined : json['ProjectName'],
        'projectId': json['ProjectId'] == null ? undefined : json['ProjectId'],
        'reopenStatus': json['ReopenStatus'] == null ? undefined : json['ReopenStatus'],
        'reopenStatusJira': json['ReopenStatusJira'] == null ? undefined : json['ReopenStatusJira'],
        'reporter': json['Reporter'] == null ? undefined : json['Reporter'],
        'reporterName': json['ReporterName'] == null ? undefined : json['ReporterName'],
        'url': json['Url'],
        'usernameOrEmail': json['UsernameOrEmail'],
        'webhookUrl': json['WebhookUrl'] == null ? undefined : json['WebhookUrl'],
        'templateType': json['TemplateType'] == null ? undefined : json['TemplateType'],
        'isRemoveRequestResponse': json['IsRemoveRequestResponse'] == null ? undefined : json['IsRemoveRequestResponse'],
        'epicName': json['EpicName'] == null ? undefined : json['EpicName'],
        'epicNameCustomFieldName': json['EpicNameCustomFieldName'] == null ? undefined : json['EpicNameCustomFieldName'],
        'epicKey': json['EpicKey'] == null ? undefined : json['EpicKey'],
        'epicKeyCustomFieldName': json['EpicKeyCustomFieldName'] == null ? undefined : json['EpicKeyCustomFieldName'],
        'epicSelectionType': json['EpicSelectionType'] == null ? undefined : json['EpicSelectionType'],
        'priorityMappings': json['PriorityMappings'] == null ? undefined : (json['PriorityMappings'].map(JiraPriorityMapping_1.JiraPriorityMappingFromJSON)),
        'type': json['Type'] == null ? undefined : json['Type'],
        'genericErrorMessage': json['GenericErrorMessage'] == null ? undefined : json['GenericErrorMessage'],
        'identifier': json['Identifier'] == null ? undefined : json['Identifier'],
        'testMessageBody': json['TestMessageBody'] == null ? undefined : json['TestMessageBody'],
        'testMessageTitle': json['TestMessageTitle'] == null ? undefined : json['TestMessageTitle'],
        'name': json['Name'] == null ? undefined : json['Name'],
        'integrationVersion': json['IntegrationVersion'] == null ? undefined : json['IntegrationVersion'],
        'accountID': json['AccountID'] == null ? undefined : json['AccountID'],
        'customFields': json['CustomFields'] == null ? undefined : (json['CustomFields'].map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmFromJSON)),
        'resolvedStatus': json['ResolvedStatus'] == null ? undefined : json['ResolvedStatus'],
        'titleFormat': json['TitleFormat'],
        'integrationWizardResultModel': json['IntegrationWizardResultModel'] == null ? undefined : (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelFromJSON)(json['IntegrationWizardResultModel']),
        'id': json['Id'] == null ? undefined : json['Id'],
        'state': json['State'] == null ? undefined : json['State'],
    };
}
exports.JiraIntegrationInfoModelFromJSONTyped = JiraIntegrationInfoModelFromJSONTyped;
function JiraIntegrationInfoModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'AssignedTo': value['assignedTo'],
        'AssignedToName': value['assignedToName'],
        'AutoAssignToPerson': value['autoAssignToPerson'],
        'DueDays': value['dueDays'],
        'IssueType': value['issueType'],
        'IssueTypeId': value['issueTypeId'],
        'Labels': value['labels'],
        'Components': value['components'],
        'MappedJiraUsers': value['mappedJiraUsers'] == null ? undefined : (value['mappedJiraUsers'].map(IntegrationUserMappingItemModel_1.IntegrationUserMappingItemModelToJSON)),
        'Password': value['password'],
        'Priority': value['priority'],
        'SecurityLevel': value['securityLevel'],
        'ProjectKey': value['projectKey'],
        'ProjectName': value['projectName'],
        'ProjectId': value['projectId'],
        'ReopenStatusJira': value['reopenStatusJira'],
        'Reporter': value['reporter'],
        'ReporterName': value['reporterName'],
        'Url': value['url'],
        'UsernameOrEmail': value['usernameOrEmail'],
        'TemplateType': value['templateType'],
        'IsRemoveRequestResponse': value['isRemoveRequestResponse'],
        'EpicName': value['epicName'],
        'EpicNameCustomFieldName': value['epicNameCustomFieldName'],
        'EpicKey': value['epicKey'],
        'EpicKeyCustomFieldName': value['epicKeyCustomFieldName'],
        'PriorityMappings': value['priorityMappings'] == null ? undefined : (value['priorityMappings'].map(JiraPriorityMapping_1.JiraPriorityMappingToJSON)),
        'Name': value['name'],
        'IntegrationVersion': value['integrationVersion'],
        'AccountID': value['accountID'],
        'CustomFields': value['customFields'] == null ? undefined : (value['customFields'].map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmToJSON)),
        'ResolvedStatus': value['resolvedStatus'],
        'TitleFormat': value['titleFormat'],
        'IntegrationWizardResultModel': (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelToJSON)(value['integrationWizardResultModel']),
        'Id': value['id'],
        'State': value['state'],
    };
}
exports.JiraIntegrationInfoModelToJSON = JiraIntegrationInfoModelToJSON;
//# sourceMappingURL=JiraIntegrationInfoModel.js.map