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
exports.GitHubIntegrationInfoModelToJSON = exports.GitHubIntegrationInfoModelFromJSONTyped = exports.GitHubIntegrationInfoModelFromJSON = exports.instanceOfGitHubIntegrationInfoModel = exports.GitHubIntegrationInfoModelTemplateTypeEnum = exports.GitHubIntegrationInfoModelTypeEnum = void 0;
const runtime_1 = require("../runtime");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const IntegrationWizardResultModel_1 = require("./IntegrationWizardResultModel");
/**
 * @export
 */
exports.GitHubIntegrationInfoModelTypeEnum = {
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
exports.GitHubIntegrationInfoModelTemplateTypeEnum = {
    Standard: 'Standard',
    Detailed: 'Detailed'
};
/**
 * Check if a given object implements the GitHubIntegrationInfoModel interface.
 */
function instanceOfGitHubIntegrationInfoModel(value) {
    let isInstance = true;
    isInstance = isInstance && "accessToken" in value;
    isInstance = isInstance && "serverUrl" in value;
    isInstance = isInstance && "repository" in value;
    isInstance = isInstance && "username" in value;
    isInstance = isInstance && "titleFormat" in value;
    return isInstance;
}
exports.instanceOfGitHubIntegrationInfoModel = instanceOfGitHubIntegrationInfoModel;
function GitHubIntegrationInfoModelFromJSON(json) {
    return GitHubIntegrationInfoModelFromJSONTyped(json, false);
}
exports.GitHubIntegrationInfoModelFromJSON = GitHubIntegrationInfoModelFromJSON;
function GitHubIntegrationInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'accessToken': json['AccessToken'],
        'serverUrl': json['ServerUrl'],
        'assignee': !(0, runtime_1.exists)(json, 'Assignee') ? undefined : json['Assignee'],
        'labels': !(0, runtime_1.exists)(json, 'Labels') ? undefined : json['Labels'],
        'repository': json['Repository'],
        'username': json['Username'],
        'organization': !(0, runtime_1.exists)(json, 'Organization') ? undefined : json['Organization'],
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
exports.GitHubIntegrationInfoModelFromJSONTyped = GitHubIntegrationInfoModelFromJSONTyped;
function GitHubIntegrationInfoModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AccessToken': value.accessToken,
        'ServerUrl': value.serverUrl,
        'Assignee': value.assignee,
        'Labels': value.labels,
        'Repository': value.repository,
        'Username': value.username,
        'Organization': value.organization,
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
exports.GitHubIntegrationInfoModelToJSON = GitHubIntegrationInfoModelToJSON;
//# sourceMappingURL=GitHubIntegrationInfoModel.js.map