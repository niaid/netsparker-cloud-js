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
exports.ClubhouseIntegrationInfoModelToJSON = exports.ClubhouseIntegrationInfoModelFromJSONTyped = exports.ClubhouseIntegrationInfoModelFromJSON = exports.instanceOfClubhouseIntegrationInfoModel = exports.ClubhouseIntegrationInfoModelTemplateTypeEnum = exports.ClubhouseIntegrationInfoModelTypeEnum = exports.ClubhouseIntegrationInfoModelClubhouseStoryTypeEnum = void 0;
const runtime_1 = require("../runtime");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
/**
 * @export
 */
exports.ClubhouseIntegrationInfoModelClubhouseStoryTypeEnum = {
    Bug: 'Bug',
    Feature: 'Feature',
    Chore: 'Chore'
};
/**
 * @export
 */
exports.ClubhouseIntegrationInfoModelTypeEnum = {
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
exports.ClubhouseIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * Check if a given object implements the ClubhouseIntegrationInfoModel interface.
 */
function instanceOfClubhouseIntegrationInfoModel(value) {
    let isInstance = true;
    isInstance = isInstance && "apiToken" in value;
    isInstance = isInstance && "projectId" in value;
    isInstance = isInstance && "dueDays" in value;
    isInstance = isInstance && "titleFormat" in value;
    return isInstance;
}
exports.instanceOfClubhouseIntegrationInfoModel = instanceOfClubhouseIntegrationInfoModel;
function ClubhouseIntegrationInfoModelFromJSON(json) {
    return ClubhouseIntegrationInfoModelFromJSONTyped(json, false);
}
exports.ClubhouseIntegrationInfoModelFromJSON = ClubhouseIntegrationInfoModelFromJSON;
function ClubhouseIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'apiToken': json['ApiToken'],
        'projectId': json['ProjectId'],
        'clubhouseStoryType': !(0, runtime_1.exists)(json, 'ClubhouseStoryType') ? undefined : json['ClubhouseStoryType'],
        'epicId': !(0, runtime_1.exists)(json, 'EpicId') ? undefined : json['EpicId'],
        'stateId': !(0, runtime_1.exists)(json, 'StateId') ? undefined : json['StateId'],
        'requesterId': !(0, runtime_1.exists)(json, 'RequesterId') ? undefined : json['RequesterId'],
        'ownerIds': !(0, runtime_1.exists)(json, 'OwnerIds') ? undefined : json['OwnerIds'],
        'followerIds': !(0, runtime_1.exists)(json, 'FollowerIds') ? undefined : json['FollowerIds'],
        'dueDays': json['DueDays'],
        'labels': !(0, runtime_1.exists)(json, 'Labels') ? undefined : json['Labels'],
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
exports.ClubhouseIntegrationInfoModelFromJSONTyped = ClubhouseIntegrationInfoModelFromJSONTyped;
function ClubhouseIntegrationInfoModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'ApiToken': value.apiToken,
        'ProjectId': value.projectId,
        'ClubhouseStoryType': value.clubhouseStoryType,
        'EpicId': value.epicId,
        'StateId': value.stateId,
        'RequesterId': value.requesterId,
        'OwnerIds': value.ownerIds,
        'FollowerIds': value.followerIds,
        'DueDays': value.dueDays,
        'Labels': value.labels,
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
exports.ClubhouseIntegrationInfoModelToJSON = ClubhouseIntegrationInfoModelToJSON;
//# sourceMappingURL=ClubhouseIntegrationInfoModel.js.map