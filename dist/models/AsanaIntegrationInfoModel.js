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
exports.AsanaIntegrationInfoModelToJSON = exports.AsanaIntegrationInfoModelFromJSONTyped = exports.AsanaIntegrationInfoModelFromJSON = exports.instanceOfAsanaIntegrationInfoModel = exports.AsanaIntegrationInfoModelTemplateTypeEnum = exports.AsanaIntegrationInfoModelTypeEnum = void 0;
const runtime_1 = require("../runtime");
const AsanaProject_1 = require("./AsanaProject");
const AsanaTag_1 = require("./AsanaTag");
const AsanaUser_1 = require("./AsanaUser");
const AsanaWorkspace_1 = require("./AsanaWorkspace");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
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
 * Check if a given object implements the AsanaIntegrationInfoModel interface.
 */
function instanceOfAsanaIntegrationInfoModel(value) {
    let isInstance = true;
    isInstance = isInstance && "accessToken" in value;
    isInstance = isInstance && "projectId" in value;
    isInstance = isInstance && "dueDays" in value;
    isInstance = isInstance && "titleFormat" in value;
    return isInstance;
}
exports.instanceOfAsanaIntegrationInfoModel = instanceOfAsanaIntegrationInfoModel;
function AsanaIntegrationInfoModelFromJSON(json) {
    return AsanaIntegrationInfoModelFromJSONTyped(json, false);
}
exports.AsanaIntegrationInfoModelFromJSON = AsanaIntegrationInfoModelFromJSON;
function AsanaIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'accessToken': json['AccessToken'],
        'projectId': json['ProjectId'],
        'workspaceId': !(0, runtime_1.exists)(json, 'WorkspaceId') ? undefined : json['WorkspaceId'],
        'assignee': !(0, runtime_1.exists)(json, 'Assignee') ? undefined : json['Assignee'],
        'followerIds': !(0, runtime_1.exists)(json, 'FollowerIds') ? undefined : json['FollowerIds'],
        'dueDays': json['DueDays'],
        'tagIds': !(0, runtime_1.exists)(json, 'TagIds') ? undefined : json['TagIds'],
        'workspaceList': !(0, runtime_1.exists)(json, 'WorkspaceList') ? undefined : (json['WorkspaceList'].map(AsanaWorkspace_1.AsanaWorkspaceFromJSON)),
        'projectList': !(0, runtime_1.exists)(json, 'ProjectList') ? undefined : (json['ProjectList'].map(AsanaProject_1.AsanaProjectFromJSON)),
        'assigneeList': !(0, runtime_1.exists)(json, 'AssigneeList') ? undefined : (json['AssigneeList'].map(AsanaUser_1.AsanaUserFromJSON)),
        'followerList': !(0, runtime_1.exists)(json, 'FollowerList') ? undefined : (json['FollowerList'].map(AsanaUser_1.AsanaUserFromJSON)),
        'tagList': !(0, runtime_1.exists)(json, 'TagList') ? undefined : (json['TagList'].map(AsanaTag_1.AsanaTagFromJSON)),
        'followersSelected': !(0, runtime_1.exists)(json, 'FollowersSelected') ? undefined : json['FollowersSelected'],
        'tagsSelected': !(0, runtime_1.exists)(json, 'TagsSelected') ? undefined : json['TagsSelected'],
        'integrationWizardResultModel': !(0, runtime_1.exists)(json, 'IntegrationWizardResultModel') ? undefined : (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelFromJSON)(json['IntegrationWizardResultModel']),
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
    };
}
exports.AsanaIntegrationInfoModelFromJSONTyped = AsanaIntegrationInfoModelFromJSONTyped;
function AsanaIntegrationInfoModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AccessToken': value.accessToken,
        'ProjectId': value.projectId,
        'WorkspaceId': value.workspaceId,
        'Assignee': value.assignee,
        'FollowerIds': value.followerIds,
        'DueDays': value.dueDays,
        'TagIds': value.tagIds,
        'WorkspaceList': value.workspaceList === undefined ? undefined : (value.workspaceList.map(AsanaWorkspace_1.AsanaWorkspaceToJSON)),
        'ProjectList': value.projectList === undefined ? undefined : (value.projectList.map(AsanaProject_1.AsanaProjectToJSON)),
        'AssigneeList': value.assigneeList === undefined ? undefined : (value.assigneeList.map(AsanaUser_1.AsanaUserToJSON)),
        'FollowerList': value.followerList === undefined ? undefined : (value.followerList.map(AsanaUser_1.AsanaUserToJSON)),
        'TagList': value.tagList === undefined ? undefined : (value.tagList.map(AsanaTag_1.AsanaTagToJSON)),
        'IntegrationWizardResultModel': (0, IntegrationWizardResultModel_1.IntegrationWizardResultModelToJSON)(value.integrationWizardResultModel),
        'Name': value.name,
        'IntegrationVersion': value.integrationVersion,
        'AccountID': value.accountID,
        'CustomFields': value.customFields === undefined ? undefined : (value.customFields.map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmToJSON)),
        'TemplateType': value.templateType,
        'ReopenStatus': value.reopenStatus,
        'ResolvedStatus': value.resolvedStatus,
        'TitleFormat': value.titleFormat,
    };
}
exports.AsanaIntegrationInfoModelToJSON = AsanaIntegrationInfoModelToJSON;
//# sourceMappingURL=AsanaIntegrationInfoModel.js.map