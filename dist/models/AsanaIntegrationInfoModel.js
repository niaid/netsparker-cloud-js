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
exports.AsanaIntegrationInfoModelToJSON = exports.AsanaIntegrationInfoModelFromJSONTyped = exports.AsanaIntegrationInfoModelFromJSON = exports.instanceOfAsanaIntegrationInfoModel = exports.AsanaIntegrationInfoModelStateEnum = exports.AsanaIntegrationInfoModelTemplateTypeEnum = exports.AsanaIntegrationInfoModelTypeEnum = void 0;
const AsanaTag_1 = require("./AsanaTag");
const AsanaUser_1 = require("./AsanaUser");
const AsanaProject_1 = require("./AsanaProject");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const AsanaWorkspace_1 = require("./AsanaWorkspace");
/**
 * @export
 */
exports.AsanaIntegrationInfoModelTypeEnum = {
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
exports.AsanaIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * @export
 */
exports.AsanaIntegrationInfoModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
};
/**
 * Check if a given object implements the AsanaIntegrationInfoModel interface.
 */
function instanceOfAsanaIntegrationInfoModel(value) {
    if (!('accessToken' in value))
        return false;
    if (!('projectId' in value))
        return false;
    if (!('dueDays' in value))
        return false;
    if (!('titleFormat' in value))
        return false;
    return true;
}
exports.instanceOfAsanaIntegrationInfoModel = instanceOfAsanaIntegrationInfoModel;
function AsanaIntegrationInfoModelFromJSON(json) {
    return AsanaIntegrationInfoModelFromJSONTyped(json, false);
}
exports.AsanaIntegrationInfoModelFromJSON = AsanaIntegrationInfoModelFromJSON;
function AsanaIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'accessToken': json['AccessToken'],
        'projectId': json['ProjectId'],
        'workspaceId': json['WorkspaceId'] == null ? undefined : json['WorkspaceId'],
        'assignee': json['Assignee'] == null ? undefined : json['Assignee'],
        'followerIds': json['FollowerIds'] == null ? undefined : json['FollowerIds'],
        'dueDays': json['DueDays'],
        'tagIds': json['TagIds'] == null ? undefined : json['TagIds'],
        'workspaceList': json['WorkspaceList'] == null ? undefined : (json['WorkspaceList'].map(AsanaWorkspace_1.AsanaWorkspaceFromJSON)),
        'projectList': json['ProjectList'] == null ? undefined : (json['ProjectList'].map(AsanaProject_1.AsanaProjectFromJSON)),
        'assigneeList': json['AssigneeList'] == null ? undefined : (json['AssigneeList'].map(AsanaUser_1.AsanaUserFromJSON)),
        'followerList': json['FollowerList'] == null ? undefined : (json['FollowerList'].map(AsanaUser_1.AsanaUserFromJSON)),
        'tagList': json['TagList'] == null ? undefined : (json['TagList'].map(AsanaTag_1.AsanaTagFromJSON)),
        'followersSelected': json['FollowersSelected'] == null ? undefined : json['FollowersSelected'],
        'tagsSelected': json['TagsSelected'] == null ? undefined : json['TagsSelected'],
        'integrationWizardResultModel': json['IntegrationWizardResultModel'] == null ? undefined : (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelFromJSON)(json['IntegrationWizardResultModel']),
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
        'id': json['Id'] == null ? undefined : json['Id'],
        'state': json['State'] == null ? undefined : json['State'],
    };
}
exports.AsanaIntegrationInfoModelFromJSONTyped = AsanaIntegrationInfoModelFromJSONTyped;
function AsanaIntegrationInfoModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'AccessToken': value['accessToken'],
        'ProjectId': value['projectId'],
        'WorkspaceId': value['workspaceId'],
        'Assignee': value['assignee'],
        'FollowerIds': value['followerIds'],
        'DueDays': value['dueDays'],
        'TagIds': value['tagIds'],
        'WorkspaceList': value['workspaceList'] == null ? undefined : (value['workspaceList'].map(AsanaWorkspace_1.AsanaWorkspaceToJSON)),
        'ProjectList': value['projectList'] == null ? undefined : (value['projectList'].map(AsanaProject_1.AsanaProjectToJSON)),
        'AssigneeList': value['assigneeList'] == null ? undefined : (value['assigneeList'].map(AsanaUser_1.AsanaUserToJSON)),
        'FollowerList': value['followerList'] == null ? undefined : (value['followerList'].map(AsanaUser_1.AsanaUserToJSON)),
        'TagList': value['tagList'] == null ? undefined : (value['tagList'].map(AsanaTag_1.AsanaTagToJSON)),
        'IntegrationWizardResultModel': (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelToJSON)(value['integrationWizardResultModel']),
        'Name': value['name'],
        'IntegrationVersion': value['integrationVersion'],
        'AccountID': value['accountID'],
        'CustomFields': value['customFields'] == null ? undefined : (value['customFields'].map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmToJSON)),
        'TemplateType': value['templateType'],
        'ReopenStatus': value['reopenStatus'],
        'ResolvedStatus': value['resolvedStatus'],
        'TitleFormat': value['titleFormat'],
        'Id': value['id'],
        'State': value['state'],
    };
}
exports.AsanaIntegrationInfoModelToJSON = AsanaIntegrationInfoModelToJSON;
//# sourceMappingURL=AsanaIntegrationInfoModel.js.map