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
exports.PivotalTrackerIntegrationInfoModelToJSON = exports.PivotalTrackerIntegrationInfoModelFromJSONTyped = exports.PivotalTrackerIntegrationInfoModelFromJSON = exports.instanceOfPivotalTrackerIntegrationInfoModel = exports.PivotalTrackerIntegrationInfoModelStateEnum = exports.PivotalTrackerIntegrationInfoModelTemplateTypeEnum = exports.PivotalTrackerIntegrationInfoModelTypeEnum = exports.PivotalTrackerIntegrationInfoModelStoryTypeEnum = void 0;
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
/**
 * @export
 */
exports.PivotalTrackerIntegrationInfoModelStoryTypeEnum = {
    Bug: 'Bug',
    Feature: 'Feature',
    Chore: 'Chore',
    Release: 'Release'
};
/**
 * @export
 */
exports.PivotalTrackerIntegrationInfoModelTypeEnum = {
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
exports.PivotalTrackerIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * @export
 */
exports.PivotalTrackerIntegrationInfoModelStateEnum = {
    Active: 'Active',
    Suspended: 'Suspended'
};
/**
 * Check if a given object implements the PivotalTrackerIntegrationInfoModel interface.
 */
function instanceOfPivotalTrackerIntegrationInfoModel(value) {
    if (!('apiToken' in value))
        return false;
    if (!('projectId' in value))
        return false;
    if (!('storyType' in value))
        return false;
    if (!('titleFormat' in value))
        return false;
    return true;
}
exports.instanceOfPivotalTrackerIntegrationInfoModel = instanceOfPivotalTrackerIntegrationInfoModel;
function PivotalTrackerIntegrationInfoModelFromJSON(json) {
    return PivotalTrackerIntegrationInfoModelFromJSONTyped(json, false);
}
exports.PivotalTrackerIntegrationInfoModelFromJSON = PivotalTrackerIntegrationInfoModelFromJSON;
function PivotalTrackerIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'apiToken': json['ApiToken'],
        'projectId': json['ProjectId'],
        'storyType': json['StoryType'],
        'ownerIds': json['OwnerIds'] == null ? undefined : json['OwnerIds'],
        'labels': json['Labels'] == null ? undefined : json['Labels'],
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
exports.PivotalTrackerIntegrationInfoModelFromJSONTyped = PivotalTrackerIntegrationInfoModelFromJSONTyped;
function PivotalTrackerIntegrationInfoModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'ApiToken': value['apiToken'],
        'ProjectId': value['projectId'],
        'StoryType': value['storyType'],
        'OwnerIds': value['ownerIds'],
        'Labels': value['labels'],
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
exports.PivotalTrackerIntegrationInfoModelToJSON = PivotalTrackerIntegrationInfoModelToJSON;
//# sourceMappingURL=PivotalTrackerIntegrationInfoModel.js.map