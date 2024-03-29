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
exports.ScanNotificationIntegrationViewModelToJSON = exports.ScanNotificationIntegrationViewModelFromJSONTyped = exports.ScanNotificationIntegrationViewModelFromJSON = exports.instanceOfScanNotificationIntegrationViewModel = exports.ScanNotificationIntegrationViewModelCategoryEnum = exports.ScanNotificationIntegrationViewModelTypeEnum = void 0;
const runtime_1 = require("../runtime");
const AsanaIntegrationInfoModel_1 = require("./AsanaIntegrationInfoModel");
const AzureDevOpsIntegrationInfoModel_1 = require("./AzureDevOpsIntegrationInfoModel");
const AzureKeyVaultIntegrationInfoModel_1 = require("./AzureKeyVaultIntegrationInfoModel");
const BitbucketIntegrationInfoModel_1 = require("./BitbucketIntegrationInfoModel");
const BugzillaIntegrationInfoModel_1 = require("./BugzillaIntegrationInfoModel");
const ClubhouseIntegrationInfoModel_1 = require("./ClubhouseIntegrationInfoModel");
const CyberArkVaultIntegrationInfoModel_1 = require("./CyberArkVaultIntegrationInfoModel");
const DefectDojoIntegrationInfoModel_1 = require("./DefectDojoIntegrationInfoModel");
const FogBugzIntegrationInfoModel_1 = require("./FogBugzIntegrationInfoModel");
const FreshserviceIntegrationInfoModel_1 = require("./FreshserviceIntegrationInfoModel");
const GitHubIntegrationInfoModel_1 = require("./GitHubIntegrationInfoModel");
const GitLabIntegrationInfoModel_1 = require("./GitLabIntegrationInfoModel");
const HashicorpVaultIntegrationInfoModel_1 = require("./HashicorpVaultIntegrationInfoModel");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const JazzTeamIntegrationInfoModel_1 = require("./JazzTeamIntegrationInfoModel");
const JiraIntegrationInfoModel_1 = require("./JiraIntegrationInfoModel");
const KafkaIntegrationInfoModel_1 = require("./KafkaIntegrationInfoModel");
const KennaIntegrationInfoModel_1 = require("./KennaIntegrationInfoModel");
const MattermostIntegrationInfoModel_1 = require("./MattermostIntegrationInfoModel");
const MicrosoftTeamsIntegrationInfoModel_1 = require("./MicrosoftTeamsIntegrationInfoModel");
const PagerDutyIntegrationInfoModel_1 = require("./PagerDutyIntegrationInfoModel");
const PivotalTrackerIntegrationInfoModel_1 = require("./PivotalTrackerIntegrationInfoModel");
const RedmineIntegrationInfoModel_1 = require("./RedmineIntegrationInfoModel");
const ServiceNowIntegrationInfoModel_1 = require("./ServiceNowIntegrationInfoModel");
const ServiceNowVRMModel_1 = require("./ServiceNowVRMModel");
const SlackIntegrationInfoModel_1 = require("./SlackIntegrationInfoModel");
const TFSIntegrationInfoModel_1 = require("./TFSIntegrationInfoModel");
const TrelloIntegrationInfoModel_1 = require("./TrelloIntegrationInfoModel");
const UnfuddleIntegrationInfoModel_1 = require("./UnfuddleIntegrationInfoModel");
const WebhookIntegrationInfoModel_1 = require("./WebhookIntegrationInfoModel");
const YouTrackIntegrationInfoModel_1 = require("./YouTrackIntegrationInfoModel");
const ZapierIntegrationInfoModel_1 = require("./ZapierIntegrationInfoModel");
/**
 * @export
 */
exports.ScanNotificationIntegrationViewModelTypeEnum = {
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
exports.ScanNotificationIntegrationViewModelCategoryEnum = {
    IssueTrackingSystem: 'IssueTrackingSystem',
    TeamMessagingSystem: 'TeamMessagingSystem',
    SecretsAndEncryptionManagement: 'SecretsAndEncryptionManagement'
};
/**
 * Check if a given object implements the ScanNotificationIntegrationViewModel interface.
 */
function instanceOfScanNotificationIntegrationViewModel(value) {
    let isInstance = true;
    isInstance = isInstance && "name" in value;
    return isInstance;
}
exports.instanceOfScanNotificationIntegrationViewModel = instanceOfScanNotificationIntegrationViewModel;
function ScanNotificationIntegrationViewModelFromJSON(json) {
    return ScanNotificationIntegrationViewModelFromJSONTyped(json, false);
}
exports.ScanNotificationIntegrationViewModelFromJSON = ScanNotificationIntegrationViewModelFromJSON;
function ScanNotificationIntegrationViewModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': !(0, runtime_1.exists)(json, 'Id') ? undefined : json['Id'],
        'name': json['Name'],
        'notFound': !(0, runtime_1.exists)(json, 'NotFound') ? undefined : json['NotFound'],
        'type': !(0, runtime_1.exists)(json, 'Type') ? undefined : json['Type'],
        'category': !(0, runtime_1.exists)(json, 'Category') ? undefined : json['Category'],
        'asanaInfo': !(0, runtime_1.exists)(json, 'AsanaInfo') ? undefined : (0, AsanaIntegrationInfoModel_1.AsanaIntegrationInfoModelFromJSON)(json['AsanaInfo']),
        'azureDevopsInfo': !(0, runtime_1.exists)(json, 'AzureDevopsInfo') ? undefined : (0, AzureDevOpsIntegrationInfoModel_1.AzureDevOpsIntegrationInfoModelFromJSON)(json['AzureDevopsInfo']),
        'bitbucketInfo': !(0, runtime_1.exists)(json, 'BitbucketInfo') ? undefined : (0, BitbucketIntegrationInfoModel_1.BitbucketIntegrationInfoModelFromJSON)(json['BitbucketInfo']),
        'bugzilla': !(0, runtime_1.exists)(json, 'Bugzilla') ? undefined : (0, BugzillaIntegrationInfoModel_1.BugzillaIntegrationInfoModelFromJSON)(json['Bugzilla']),
        'pagerDutyInfo': !(0, runtime_1.exists)(json, 'PagerDutyInfo') ? undefined : (0, PagerDutyIntegrationInfoModel_1.PagerDutyIntegrationInfoModelFromJSON)(json['PagerDutyInfo']),
        'redmineInfo': !(0, runtime_1.exists)(json, 'RedmineInfo') ? undefined : (0, RedmineIntegrationInfoModel_1.RedmineIntegrationInfoModelFromJSON)(json['RedmineInfo']),
        'serviceNowInfo': !(0, runtime_1.exists)(json, 'ServiceNowInfo') ? undefined : (0, ServiceNowIntegrationInfoModel_1.ServiceNowIntegrationInfoModelFromJSON)(json['ServiceNowInfo']),
        'serviceNowVRMInfo': !(0, runtime_1.exists)(json, 'ServiceNowVRMInfo') ? undefined : (0, ServiceNowVRMModel_1.ServiceNowVRMModelFromJSON)(json['ServiceNowVRMInfo']),
        'slackInfo': !(0, runtime_1.exists)(json, 'SlackInfo') ? undefined : (0, SlackIntegrationInfoModel_1.SlackIntegrationInfoModelFromJSON)(json['SlackInfo']),
        'mattermostInfo': !(0, runtime_1.exists)(json, 'MattermostInfo') ? undefined : (0, MattermostIntegrationInfoModel_1.MattermostIntegrationInfoModelFromJSON)(json['MattermostInfo']),
        'tFSInfo': !(0, runtime_1.exists)(json, 'TFSInfo') ? undefined : (0, TFSIntegrationInfoModel_1.TFSIntegrationInfoModelFromJSON)(json['TFSInfo']),
        'trelloInfo': !(0, runtime_1.exists)(json, 'TrelloInfo') ? undefined : (0, TrelloIntegrationInfoModel_1.TrelloIntegrationInfoModelFromJSON)(json['TrelloInfo']),
        'unfuddleInfo': !(0, runtime_1.exists)(json, 'UnfuddleInfo') ? undefined : (0, UnfuddleIntegrationInfoModel_1.UnfuddleIntegrationInfoModelFromJSON)(json['UnfuddleInfo']),
        'webhookInfo': !(0, runtime_1.exists)(json, 'WebhookInfo') ? undefined : (0, WebhookIntegrationInfoModel_1.WebhookIntegrationInfoModelFromJSON)(json['WebhookInfo']),
        'zapierInfo': !(0, runtime_1.exists)(json, 'ZapierInfo') ? undefined : (0, ZapierIntegrationInfoModel_1.ZapierIntegrationInfoModelFromJSON)(json['ZapierInfo']),
        'vaultInfo': !(0, runtime_1.exists)(json, 'VaultInfo') ? undefined : (0, HashicorpVaultIntegrationInfoModel_1.HashicorpVaultIntegrationInfoModelFromJSON)(json['VaultInfo']),
        'cyberArkVaultInfo': !(0, runtime_1.exists)(json, 'CyberArkVaultInfo') ? undefined : (0, CyberArkVaultIntegrationInfoModel_1.CyberArkVaultIntegrationInfoModelFromJSON)(json['CyberArkVaultInfo']),
        'azureVaultInfo': !(0, runtime_1.exists)(json, 'AzureVaultInfo') ? undefined : (0, AzureKeyVaultIntegrationInfoModel_1.AzureKeyVaultIntegrationInfoModelFromJSON)(json['AzureVaultInfo']),
        'jazzTeamInfo': !(0, runtime_1.exists)(json, 'JazzTeamInfo') ? undefined : (0, JazzTeamIntegrationInfoModel_1.JazzTeamIntegrationInfoModelFromJSON)(json['JazzTeamInfo']),
        'clubhouseInfo': !(0, runtime_1.exists)(json, 'ClubhouseInfo') ? undefined : (0, ClubhouseIntegrationInfoModel_1.ClubhouseIntegrationInfoModelFromJSON)(json['ClubhouseInfo']),
        'pivotalTrackerInfo': !(0, runtime_1.exists)(json, 'PivotalTrackerInfo') ? undefined : (0, PivotalTrackerIntegrationInfoModel_1.PivotalTrackerIntegrationInfoModelFromJSON)(json['PivotalTrackerInfo']),
        'customFields': !(0, runtime_1.exists)(json, 'CustomFields') ? undefined : (json['CustomFields'].map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmFromJSON)),
        'defectDojoInfo': !(0, runtime_1.exists)(json, 'DefectDojoInfo') ? undefined : (0, DefectDojoIntegrationInfoModel_1.DefectDojoIntegrationInfoModelFromJSON)(json['DefectDojoInfo']),
        'fogBugzInfo': !(0, runtime_1.exists)(json, 'FogBugzInfo') ? undefined : (0, FogBugzIntegrationInfoModel_1.FogBugzIntegrationInfoModelFromJSON)(json['FogBugzInfo']),
        'gitHubInfo': !(0, runtime_1.exists)(json, 'GitHubInfo') ? undefined : (0, GitHubIntegrationInfoModel_1.GitHubIntegrationInfoModelFromJSON)(json['GitHubInfo']),
        'gitLabInfo': !(0, runtime_1.exists)(json, 'GitLabInfo') ? undefined : (0, GitLabIntegrationInfoModel_1.GitLabIntegrationInfoModelFromJSON)(json['GitLabInfo']),
        'jiraInfo': !(0, runtime_1.exists)(json, 'JiraInfo') ? undefined : (0, JiraIntegrationInfoModel_1.JiraIntegrationInfoModelFromJSON)(json['JiraInfo']),
        'kafkaInfo': !(0, runtime_1.exists)(json, 'KafkaInfo') ? undefined : (0, KafkaIntegrationInfoModel_1.KafkaIntegrationInfoModelFromJSON)(json['KafkaInfo']),
        'kennaInfo': !(0, runtime_1.exists)(json, 'KennaInfo') ? undefined : (0, KennaIntegrationInfoModel_1.KennaIntegrationInfoModelFromJSON)(json['KennaInfo']),
        'freshserviceInfo': !(0, runtime_1.exists)(json, 'FreshserviceInfo') ? undefined : (0, FreshserviceIntegrationInfoModel_1.FreshserviceIntegrationInfoModelFromJSON)(json['FreshserviceInfo']),
        'youTrackInfo': !(0, runtime_1.exists)(json, 'YouTrackInfo') ? undefined : (0, YouTrackIntegrationInfoModel_1.YouTrackIntegrationInfoModelFromJSON)(json['YouTrackInfo']),
        'microsoftTeamsInfo': !(0, runtime_1.exists)(json, 'MicrosoftTeamsInfo') ? undefined : (0, MicrosoftTeamsIntegrationInfoModel_1.MicrosoftTeamsIntegrationInfoModelFromJSON)(json['MicrosoftTeamsInfo']),
    };
}
exports.ScanNotificationIntegrationViewModelFromJSONTyped = ScanNotificationIntegrationViewModelFromJSONTyped;
function ScanNotificationIntegrationViewModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Id': value.id,
        'Name': value.name,
        'NotFound': value.notFound,
        'Type': value.type,
        'AsanaInfo': (0, AsanaIntegrationInfoModel_1.AsanaIntegrationInfoModelToJSON)(value.asanaInfo),
        'AzureDevopsInfo': (0, AzureDevOpsIntegrationInfoModel_1.AzureDevOpsIntegrationInfoModelToJSON)(value.azureDevopsInfo),
        'BitbucketInfo': (0, BitbucketIntegrationInfoModel_1.BitbucketIntegrationInfoModelToJSON)(value.bitbucketInfo),
        'Bugzilla': (0, BugzillaIntegrationInfoModel_1.BugzillaIntegrationInfoModelToJSON)(value.bugzilla),
        'PagerDutyInfo': (0, PagerDutyIntegrationInfoModel_1.PagerDutyIntegrationInfoModelToJSON)(value.pagerDutyInfo),
        'RedmineInfo': (0, RedmineIntegrationInfoModel_1.RedmineIntegrationInfoModelToJSON)(value.redmineInfo),
        'ServiceNowInfo': (0, ServiceNowIntegrationInfoModel_1.ServiceNowIntegrationInfoModelToJSON)(value.serviceNowInfo),
        'ServiceNowVRMInfo': (0, ServiceNowVRMModel_1.ServiceNowVRMModelToJSON)(value.serviceNowVRMInfo),
        'SlackInfo': (0, SlackIntegrationInfoModel_1.SlackIntegrationInfoModelToJSON)(value.slackInfo),
        'MattermostInfo': (0, MattermostIntegrationInfoModel_1.MattermostIntegrationInfoModelToJSON)(value.mattermostInfo),
        'TFSInfo': (0, TFSIntegrationInfoModel_1.TFSIntegrationInfoModelToJSON)(value.tFSInfo),
        'TrelloInfo': (0, TrelloIntegrationInfoModel_1.TrelloIntegrationInfoModelToJSON)(value.trelloInfo),
        'UnfuddleInfo': (0, UnfuddleIntegrationInfoModel_1.UnfuddleIntegrationInfoModelToJSON)(value.unfuddleInfo),
        'WebhookInfo': (0, WebhookIntegrationInfoModel_1.WebhookIntegrationInfoModelToJSON)(value.webhookInfo),
        'ZapierInfo': (0, ZapierIntegrationInfoModel_1.ZapierIntegrationInfoModelToJSON)(value.zapierInfo),
        'VaultInfo': (0, HashicorpVaultIntegrationInfoModel_1.HashicorpVaultIntegrationInfoModelToJSON)(value.vaultInfo),
        'CyberArkVaultInfo': (0, CyberArkVaultIntegrationInfoModel_1.CyberArkVaultIntegrationInfoModelToJSON)(value.cyberArkVaultInfo),
        'AzureVaultInfo': (0, AzureKeyVaultIntegrationInfoModel_1.AzureKeyVaultIntegrationInfoModelToJSON)(value.azureVaultInfo),
        'JazzTeamInfo': (0, JazzTeamIntegrationInfoModel_1.JazzTeamIntegrationInfoModelToJSON)(value.jazzTeamInfo),
        'ClubhouseInfo': (0, ClubhouseIntegrationInfoModel_1.ClubhouseIntegrationInfoModelToJSON)(value.clubhouseInfo),
        'PivotalTrackerInfo': (0, PivotalTrackerIntegrationInfoModel_1.PivotalTrackerIntegrationInfoModelToJSON)(value.pivotalTrackerInfo),
        'CustomFields': value.customFields === undefined ? undefined : (value.customFields.map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmToJSON)),
        'DefectDojoInfo': (0, DefectDojoIntegrationInfoModel_1.DefectDojoIntegrationInfoModelToJSON)(value.defectDojoInfo),
        'FogBugzInfo': (0, FogBugzIntegrationInfoModel_1.FogBugzIntegrationInfoModelToJSON)(value.fogBugzInfo),
        'GitHubInfo': (0, GitHubIntegrationInfoModel_1.GitHubIntegrationInfoModelToJSON)(value.gitHubInfo),
        'GitLabInfo': (0, GitLabIntegrationInfoModel_1.GitLabIntegrationInfoModelToJSON)(value.gitLabInfo),
        'JiraInfo': (0, JiraIntegrationInfoModel_1.JiraIntegrationInfoModelToJSON)(value.jiraInfo),
        'KafkaInfo': (0, KafkaIntegrationInfoModel_1.KafkaIntegrationInfoModelToJSON)(value.kafkaInfo),
        'KennaInfo': (0, KennaIntegrationInfoModel_1.KennaIntegrationInfoModelToJSON)(value.kennaInfo),
        'FreshserviceInfo': (0, FreshserviceIntegrationInfoModel_1.FreshserviceIntegrationInfoModelToJSON)(value.freshserviceInfo),
        'YouTrackInfo': (0, YouTrackIntegrationInfoModel_1.YouTrackIntegrationInfoModelToJSON)(value.youTrackInfo),
        'MicrosoftTeamsInfo': (0, MicrosoftTeamsIntegrationInfoModel_1.MicrosoftTeamsIntegrationInfoModelToJSON)(value.microsoftTeamsInfo),
    };
}
exports.ScanNotificationIntegrationViewModelToJSON = ScanNotificationIntegrationViewModelToJSON;
//# sourceMappingURL=ScanNotificationIntegrationViewModel.js.map