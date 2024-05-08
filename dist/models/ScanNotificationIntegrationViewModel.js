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
const TFSIntegrationInfoModel_1 = require("./TFSIntegrationInfoModel");
const MattermostIntegrationInfoModel_1 = require("./MattermostIntegrationInfoModel");
const ServiceNowIntegrationInfoModel_1 = require("./ServiceNowIntegrationInfoModel");
const JazzTeamIntegrationInfoModel_1 = require("./JazzTeamIntegrationInfoModel");
const GitHubIntegrationInfoModel_1 = require("./GitHubIntegrationInfoModel");
const YouTrackIntegrationInfoModel_1 = require("./YouTrackIntegrationInfoModel");
const AzureDevOpsIntegrationInfoModel_1 = require("./AzureDevOpsIntegrationInfoModel");
const BugzillaIntegrationInfoModel_1 = require("./BugzillaIntegrationInfoModel");
const SlackIntegrationInfoModel_1 = require("./SlackIntegrationInfoModel");
const WebhookIntegrationInfoModel_1 = require("./WebhookIntegrationInfoModel");
const JiraIntegrationInfoModel_1 = require("./JiraIntegrationInfoModel");
const KennaIntegrationInfoModel_1 = require("./KennaIntegrationInfoModel");
const PivotalTrackerIntegrationInfoModel_1 = require("./PivotalTrackerIntegrationInfoModel");
const RedmineIntegrationInfoModel_1 = require("./RedmineIntegrationInfoModel");
const UnfuddleIntegrationInfoModel_1 = require("./UnfuddleIntegrationInfoModel");
const FogBugzIntegrationInfoModel_1 = require("./FogBugzIntegrationInfoModel");
const KafkaIntegrationInfoModel_1 = require("./KafkaIntegrationInfoModel");
const AzureKeyVaultIntegrationInfoModel_1 = require("./AzureKeyVaultIntegrationInfoModel");
const PagerDutyIntegrationInfoModel_1 = require("./PagerDutyIntegrationInfoModel");
const TrelloIntegrationInfoModel_1 = require("./TrelloIntegrationInfoModel");
const CyberArkVaultIntegrationInfoModel_1 = require("./CyberArkVaultIntegrationInfoModel");
const ZapierIntegrationInfoModel_1 = require("./ZapierIntegrationInfoModel");
const FreshserviceIntegrationInfoModel_1 = require("./FreshserviceIntegrationInfoModel");
const ClubhouseIntegrationInfoModel_1 = require("./ClubhouseIntegrationInfoModel");
const DefectDojoIntegrationInfoModel_1 = require("./DefectDojoIntegrationInfoModel");
const MicrosoftTeamsIntegrationInfoModel_1 = require("./MicrosoftTeamsIntegrationInfoModel");
const BitbucketIntegrationInfoModel_1 = require("./BitbucketIntegrationInfoModel");
const ServiceNowVRMModel_1 = require("./ServiceNowVRMModel");
const IntegrationCustomFieldVm_1 = require("./IntegrationCustomFieldVm");
const AsanaIntegrationInfoModel_1 = require("./AsanaIntegrationInfoModel");
const GitLabIntegrationInfoModel_1 = require("./GitLabIntegrationInfoModel");
const HashicorpVaultIntegrationInfoModel_1 = require("./HashicorpVaultIntegrationInfoModel");
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
    if (!('name' in value))
        return false;
    return true;
}
exports.instanceOfScanNotificationIntegrationViewModel = instanceOfScanNotificationIntegrationViewModel;
function ScanNotificationIntegrationViewModelFromJSON(json) {
    return ScanNotificationIntegrationViewModelFromJSONTyped(json, false);
}
exports.ScanNotificationIntegrationViewModelFromJSON = ScanNotificationIntegrationViewModelFromJSON;
function ScanNotificationIntegrationViewModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'id': json['Id'] == null ? undefined : json['Id'],
        'name': json['Name'],
        'notFound': json['NotFound'] == null ? undefined : json['NotFound'],
        'type': json['Type'] == null ? undefined : json['Type'],
        'category': json['Category'] == null ? undefined : json['Category'],
        'asanaInfo': json['AsanaInfo'] == null ? undefined : (0, AsanaIntegrationInfoModel_1.AsanaIntegrationInfoModelFromJSON)(json['AsanaInfo']),
        'azureDevopsInfo': json['AzureDevopsInfo'] == null ? undefined : (0, AzureDevOpsIntegrationInfoModel_1.AzureDevOpsIntegrationInfoModelFromJSON)(json['AzureDevopsInfo']),
        'bitbucketInfo': json['BitbucketInfo'] == null ? undefined : (0, BitbucketIntegrationInfoModel_1.BitbucketIntegrationInfoModelFromJSON)(json['BitbucketInfo']),
        'bugzilla': json['Bugzilla'] == null ? undefined : (0, BugzillaIntegrationInfoModel_1.BugzillaIntegrationInfoModelFromJSON)(json['Bugzilla']),
        'pagerDutyInfo': json['PagerDutyInfo'] == null ? undefined : (0, PagerDutyIntegrationInfoModel_1.PagerDutyIntegrationInfoModelFromJSON)(json['PagerDutyInfo']),
        'redmineInfo': json['RedmineInfo'] == null ? undefined : (0, RedmineIntegrationInfoModel_1.RedmineIntegrationInfoModelFromJSON)(json['RedmineInfo']),
        'serviceNowInfo': json['ServiceNowInfo'] == null ? undefined : (0, ServiceNowIntegrationInfoModel_1.ServiceNowIntegrationInfoModelFromJSON)(json['ServiceNowInfo']),
        'serviceNowVRMInfo': json['ServiceNowVRMInfo'] == null ? undefined : (0, ServiceNowVRMModel_1.ServiceNowVRMModelFromJSON)(json['ServiceNowVRMInfo']),
        'slackInfo': json['SlackInfo'] == null ? undefined : (0, SlackIntegrationInfoModel_1.SlackIntegrationInfoModelFromJSON)(json['SlackInfo']),
        'mattermostInfo': json['MattermostInfo'] == null ? undefined : (0, MattermostIntegrationInfoModel_1.MattermostIntegrationInfoModelFromJSON)(json['MattermostInfo']),
        'tFSInfo': json['TFSInfo'] == null ? undefined : (0, TFSIntegrationInfoModel_1.TFSIntegrationInfoModelFromJSON)(json['TFSInfo']),
        'trelloInfo': json['TrelloInfo'] == null ? undefined : (0, TrelloIntegrationInfoModel_1.TrelloIntegrationInfoModelFromJSON)(json['TrelloInfo']),
        'unfuddleInfo': json['UnfuddleInfo'] == null ? undefined : (0, UnfuddleIntegrationInfoModel_1.UnfuddleIntegrationInfoModelFromJSON)(json['UnfuddleInfo']),
        'webhookInfo': json['WebhookInfo'] == null ? undefined : (0, WebhookIntegrationInfoModel_1.WebhookIntegrationInfoModelFromJSON)(json['WebhookInfo']),
        'zapierInfo': json['ZapierInfo'] == null ? undefined : (0, ZapierIntegrationInfoModel_1.ZapierIntegrationInfoModelFromJSON)(json['ZapierInfo']),
        'vaultInfo': json['VaultInfo'] == null ? undefined : (0, HashicorpVaultIntegrationInfoModel_1.HashicorpVaultIntegrationInfoModelFromJSON)(json['VaultInfo']),
        'cyberArkVaultInfo': json['CyberArkVaultInfo'] == null ? undefined : (0, CyberArkVaultIntegrationInfoModel_1.CyberArkVaultIntegrationInfoModelFromJSON)(json['CyberArkVaultInfo']),
        'azureVaultInfo': json['AzureVaultInfo'] == null ? undefined : (0, AzureKeyVaultIntegrationInfoModel_1.AzureKeyVaultIntegrationInfoModelFromJSON)(json['AzureVaultInfo']),
        'jazzTeamInfo': json['JazzTeamInfo'] == null ? undefined : (0, JazzTeamIntegrationInfoModel_1.JazzTeamIntegrationInfoModelFromJSON)(json['JazzTeamInfo']),
        'clubhouseInfo': json['ClubhouseInfo'] == null ? undefined : (0, ClubhouseIntegrationInfoModel_1.ClubhouseIntegrationInfoModelFromJSON)(json['ClubhouseInfo']),
        'pivotalTrackerInfo': json['PivotalTrackerInfo'] == null ? undefined : (0, PivotalTrackerIntegrationInfoModel_1.PivotalTrackerIntegrationInfoModelFromJSON)(json['PivotalTrackerInfo']),
        'customFields': json['CustomFields'] == null ? undefined : (json['CustomFields'].map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmFromJSON)),
        'defectDojoInfo': json['DefectDojoInfo'] == null ? undefined : (0, DefectDojoIntegrationInfoModel_1.DefectDojoIntegrationInfoModelFromJSON)(json['DefectDojoInfo']),
        'fogBugzInfo': json['FogBugzInfo'] == null ? undefined : (0, FogBugzIntegrationInfoModel_1.FogBugzIntegrationInfoModelFromJSON)(json['FogBugzInfo']),
        'gitHubInfo': json['GitHubInfo'] == null ? undefined : (0, GitHubIntegrationInfoModel_1.GitHubIntegrationInfoModelFromJSON)(json['GitHubInfo']),
        'gitLabInfo': json['GitLabInfo'] == null ? undefined : (0, GitLabIntegrationInfoModel_1.GitLabIntegrationInfoModelFromJSON)(json['GitLabInfo']),
        'jiraInfo': json['JiraInfo'] == null ? undefined : (0, JiraIntegrationInfoModel_1.JiraIntegrationInfoModelFromJSON)(json['JiraInfo']),
        'kafkaInfo': json['KafkaInfo'] == null ? undefined : (0, KafkaIntegrationInfoModel_1.KafkaIntegrationInfoModelFromJSON)(json['KafkaInfo']),
        'kennaInfo': json['KennaInfo'] == null ? undefined : (0, KennaIntegrationInfoModel_1.KennaIntegrationInfoModelFromJSON)(json['KennaInfo']),
        'freshserviceInfo': json['FreshserviceInfo'] == null ? undefined : (0, FreshserviceIntegrationInfoModel_1.FreshserviceIntegrationInfoModelFromJSON)(json['FreshserviceInfo']),
        'youTrackInfo': json['YouTrackInfo'] == null ? undefined : (0, YouTrackIntegrationInfoModel_1.YouTrackIntegrationInfoModelFromJSON)(json['YouTrackInfo']),
        'microsoftTeamsInfo': json['MicrosoftTeamsInfo'] == null ? undefined : (0, MicrosoftTeamsIntegrationInfoModel_1.MicrosoftTeamsIntegrationInfoModelFromJSON)(json['MicrosoftTeamsInfo']),
    };
}
exports.ScanNotificationIntegrationViewModelFromJSONTyped = ScanNotificationIntegrationViewModelFromJSONTyped;
function ScanNotificationIntegrationViewModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Id': value['id'],
        'Name': value['name'],
        'NotFound': value['notFound'],
        'Type': value['type'],
        'AsanaInfo': (0, AsanaIntegrationInfoModel_1.AsanaIntegrationInfoModelToJSON)(value['asanaInfo']),
        'AzureDevopsInfo': (0, AzureDevOpsIntegrationInfoModel_1.AzureDevOpsIntegrationInfoModelToJSON)(value['azureDevopsInfo']),
        'BitbucketInfo': (0, BitbucketIntegrationInfoModel_1.BitbucketIntegrationInfoModelToJSON)(value['bitbucketInfo']),
        'Bugzilla': (0, BugzillaIntegrationInfoModel_1.BugzillaIntegrationInfoModelToJSON)(value['bugzilla']),
        'PagerDutyInfo': (0, PagerDutyIntegrationInfoModel_1.PagerDutyIntegrationInfoModelToJSON)(value['pagerDutyInfo']),
        'RedmineInfo': (0, RedmineIntegrationInfoModel_1.RedmineIntegrationInfoModelToJSON)(value['redmineInfo']),
        'ServiceNowInfo': (0, ServiceNowIntegrationInfoModel_1.ServiceNowIntegrationInfoModelToJSON)(value['serviceNowInfo']),
        'ServiceNowVRMInfo': (0, ServiceNowVRMModel_1.ServiceNowVRMModelToJSON)(value['serviceNowVRMInfo']),
        'SlackInfo': (0, SlackIntegrationInfoModel_1.SlackIntegrationInfoModelToJSON)(value['slackInfo']),
        'MattermostInfo': (0, MattermostIntegrationInfoModel_1.MattermostIntegrationInfoModelToJSON)(value['mattermostInfo']),
        'TFSInfo': (0, TFSIntegrationInfoModel_1.TFSIntegrationInfoModelToJSON)(value['tFSInfo']),
        'TrelloInfo': (0, TrelloIntegrationInfoModel_1.TrelloIntegrationInfoModelToJSON)(value['trelloInfo']),
        'UnfuddleInfo': (0, UnfuddleIntegrationInfoModel_1.UnfuddleIntegrationInfoModelToJSON)(value['unfuddleInfo']),
        'WebhookInfo': (0, WebhookIntegrationInfoModel_1.WebhookIntegrationInfoModelToJSON)(value['webhookInfo']),
        'ZapierInfo': (0, ZapierIntegrationInfoModel_1.ZapierIntegrationInfoModelToJSON)(value['zapierInfo']),
        'VaultInfo': (0, HashicorpVaultIntegrationInfoModel_1.HashicorpVaultIntegrationInfoModelToJSON)(value['vaultInfo']),
        'CyberArkVaultInfo': (0, CyberArkVaultIntegrationInfoModel_1.CyberArkVaultIntegrationInfoModelToJSON)(value['cyberArkVaultInfo']),
        'AzureVaultInfo': (0, AzureKeyVaultIntegrationInfoModel_1.AzureKeyVaultIntegrationInfoModelToJSON)(value['azureVaultInfo']),
        'JazzTeamInfo': (0, JazzTeamIntegrationInfoModel_1.JazzTeamIntegrationInfoModelToJSON)(value['jazzTeamInfo']),
        'ClubhouseInfo': (0, ClubhouseIntegrationInfoModel_1.ClubhouseIntegrationInfoModelToJSON)(value['clubhouseInfo']),
        'PivotalTrackerInfo': (0, PivotalTrackerIntegrationInfoModel_1.PivotalTrackerIntegrationInfoModelToJSON)(value['pivotalTrackerInfo']),
        'CustomFields': value['customFields'] == null ? undefined : (value['customFields'].map(IntegrationCustomFieldVm_1.IntegrationCustomFieldVmToJSON)),
        'DefectDojoInfo': (0, DefectDojoIntegrationInfoModel_1.DefectDojoIntegrationInfoModelToJSON)(value['defectDojoInfo']),
        'FogBugzInfo': (0, FogBugzIntegrationInfoModel_1.FogBugzIntegrationInfoModelToJSON)(value['fogBugzInfo']),
        'GitHubInfo': (0, GitHubIntegrationInfoModel_1.GitHubIntegrationInfoModelToJSON)(value['gitHubInfo']),
        'GitLabInfo': (0, GitLabIntegrationInfoModel_1.GitLabIntegrationInfoModelToJSON)(value['gitLabInfo']),
        'JiraInfo': (0, JiraIntegrationInfoModel_1.JiraIntegrationInfoModelToJSON)(value['jiraInfo']),
        'KafkaInfo': (0, KafkaIntegrationInfoModel_1.KafkaIntegrationInfoModelToJSON)(value['kafkaInfo']),
        'KennaInfo': (0, KennaIntegrationInfoModel_1.KennaIntegrationInfoModelToJSON)(value['kennaInfo']),
        'FreshserviceInfo': (0, FreshserviceIntegrationInfoModel_1.FreshserviceIntegrationInfoModelToJSON)(value['freshserviceInfo']),
        'YouTrackInfo': (0, YouTrackIntegrationInfoModel_1.YouTrackIntegrationInfoModelToJSON)(value['youTrackInfo']),
        'MicrosoftTeamsInfo': (0, MicrosoftTeamsIntegrationInfoModel_1.MicrosoftTeamsIntegrationInfoModelToJSON)(value['microsoftTeamsInfo']),
    };
}
exports.ScanNotificationIntegrationViewModelToJSON = ScanNotificationIntegrationViewModelToJSON;
//# sourceMappingURL=ScanNotificationIntegrationViewModel.js.map