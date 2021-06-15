import localVarRequest from 'request';

export * from './accessTokenTableModel';
export * from './accountLicenseApiModel';
export * from './additionalWebsiteModel';
export * from './additionalWebsitesSettingModel';
export * from './agentGroupApiDeleteModel';
export * from './agentGroupApiModel';
export * from './agentGroupApiNewModel';
export * from './agentGroupApiUpdateModel';
export * from './agentGroupModel';
export * from './agentGroupsListApiResult';
export * from './agentListApiModel';
export * from './agentListApiResult';
export * from './agentSelectionModel';
export * from './agentStatusModel';
export * from './apiFileModel';
export * from './apiScanStatusModel';
export * from './asanaIntegrationInfoModel';
export * from './asanaProject';
export * from './asanaTag';
export * from './asanaUser';
export * from './asanaWorkspace';
export * from './attackingSettingModel';
export * from './authVerificationApiResult';
export * from './authenticationProfileViewModel';
export * from './authorizationCodeTableModel';
export * from './autoCompleteSettingModel';
export * from './azureDevOpsIntegrationInfoModel';
export * from './baseResponseApiModel';
export * from './baseScanApiModel';
export * from './basicAuthenticationCredentialApiModel';
export * from './basicAuthenticationCredentialModel';
export * from './basicAuthenticationSettingApiModel';
export * from './basicAuthenticationSettingModel';
export * from './bitbucketIntegrationInfoModel';
export * from './bruteForceSettingModel';
export * from './bugzillaIntegrationInfoModel';
export * from './clientCertificateAuthenticationApiModel';
export * from './clientCertificateAuthenticationViewModel';
export * from './clubhouseIntegrationInfoModel';
export * from './contentTypeModel';
export * from './contentTypeTemplate';
export * from './crawlingSettingModel';
export * from './csrfSettingModel';
export * from './custom404SettingModel';
export * from './customFieldModel';
export * from './customHttpHeaderModel';
export * from './customHttpHeaderSetting';
export * from './customScriptPageViewModel';
export * from './customTemplateContentModel';
export * from './customTemplateModel';
export * from './cvssMetricModel';
export * from './cvssScoreValue';
export * from './cyberArkVaultIntegrationInfoModel';
export * from './deleteAgentModel';
export * from './deleteScanNotificationApiModel';
export * from './deleteWebsiteApiModel';
export * from './deleteWebsiteGroupApiModel';
export * from './discoveryApiModel';
export * from './discoveryServiceListApiResult';
export * from './discoverySettingsApiModel';
export * from './emailPatternSetting';
export * from './excludeFilter';
export * from './excludedLinkModel';
export * from './excludedUsageTrackerModel';
export * from './extensionSettingModel';
export * from './fileCache';
export * from './fogBugzIntegrationInfoModel';
export * from './formAuthenticationCustomScript';
export * from './formAuthenticationCyberArkVaultSetting';
export * from './formAuthenticationHashicorpVaultSetting';
export * from './formAuthenticationPersona';
export * from './formAuthenticationSettingApiModel';
export * from './formAuthenticationSettingModel';
export * from './formAuthenticationVerificationApiModel';
export * from './formValueSettingModel';
export * from './freshserviceEntity';
export * from './freshserviceIntegrationInfoModel';
export * from './freshserviceUser';
export * from './gitHubIntegrationInfoModel';
export * from './gitLabIntegrationInfoModel';
export * from './hashicorpVaultIntegrationInfoModel';
export * from './headerAuthenticationModel';
export * from './httpRequestSettingModel';
export * from './idNamePair';
export * from './ignorePatternSettingModel';
export * from './importedLinksSetting';
export * from './incrementalApiModel';
export * from './integrationUserMappingItemModel';
export * from './integrationWizardResultModel';
export * from './issueApiModel';
export * from './issueApiModelCvssVector';
export * from './issueApiResult';
export * from './issueApiUpdateModel';
export * from './issueHistoryApiModel';
export * from './issueReportFilterApiModel';
export * from './issueRequestContentParametersApiModel';
export * from './javaScriptSettingsModel';
export * from './jiraIntegrationInfoModel';
export * from './kafkaIntegrationInfoModel';
export * from './kennaIntegrationInfoModel';
export * from './licenseBaseModel';
export * from './logoutKeywordPatternModel';
export * from './mattermostIntegrationInfoModel';
export * from './memberApiModelListApiResult';
export * from './memberApiViewModel';
export * from './memberInvitationApiModelListApiResult';
export * from './memberInvitationApiViewModel';
export * from './microsoftTeamsIntegrationInfoModel';
export * from './nameValuePair';
export * from './newGroupScanApiModel';
export * from './newMemberApiModel';
export * from './newMemberInvitationApiModel';
export * from './newRoleApiModel';
export * from './newScanNotificationApiModel';
export * from './newScanNotificationRecipientApiModel';
export * from './newScanPolicySettingModel';
export * from './newScanTaskApiModel';
export * from './newScanTaskWithProfileApiModel';
export * from './newScheduledIncrementalScanApiModel';
export * from './newScheduledScanApiModel';
export * from './newScheduledWithProfileApiModel';
export * from './newTeamApiModel';
export * from './newWebsiteApiModel';
export * from './newWebsiteGroupApiModel';
export * from './notificationIntegrationCustomFieldModel';
export * from './notificationPriorityPair';
export * from './oAuth2SettingApiModel';
export * from './oAuth2SettingEndPointModel';
export * from './oAuth2SettingEndpoint';
export * from './oAuth2SettingModel';
export * from './otpSettings';
export * from './outsiderRecipient';
export * from './pagerDutyIntegrationInfoModel';
export * from './pciScanTaskViewModel';
export * from './permissionApiModel';
export * from './pivotalTrackerIntegrationInfoModel';
export * from './preRequestScriptSettingModel';
export * from './proxySettingsModel';
export * from './redmineIntegrationInfoModel';
export * from './reducedMemberApiViewModel';
export * from './reducedScanTaskProfile';
export * from './reducedTeamApiViewModel';
export * from './responseFields';
export * from './roleApiModelListApiResult';
export * from './roleApiViewModel';
export * from './roleWebsiteGroupMappingApiModel';
export * from './roleWebsiteGroupMappingApiViewModel';
export * from './saveScanProfileApiModel';
export * from './scanCustomReportApiModel';
export * from './scanNotificationApiModel';
export * from './scanNotificationIntegrationViewModel';
export * from './scanNotificationListApiResult';
export * from './scanNotificationRecipientApiModel';
export * from './scanNotificationRecipientUserApiModel';
export * from './scanNotificationScanTaskGroupApiModel';
export * from './scanPolicyListApiResult';
export * from './scanPolicyOptimizerOptions';
export * from './scanPolicyPatternModel';
export * from './scanPolicySettingApiModel';
export * from './scanPolicySettingItemApiModel';
export * from './scanReportApiModel';
export * from './scanTaskListApiResult';
export * from './scanTaskModel';
export * from './scanTimeWindowItemModel';
export * from './scanTimeWindowItemViewModel';
export * from './scanTimeWindowModel';
export * from './scanTimeWindowViewModel';
export * from './scheduledScanListApiResult';
export * from './scheduledScanModel';
export * from './scheduledScanRecurrenceApiModel';
export * from './scheduledScanRecurrenceViewModel';
export * from './scopeSetting';
export * from './scopeSettingModel';
export * from './securityCheckGroupModel';
export * from './securityCheckGroupParentModel';
export * from './securityCheckSetting';
export * from './selectOptionModel';
export * from './sendVerificationEmailModel';
export * from './sensitiveKeywordSettingModel';
export * from './serviceNowIntegrationInfoModel';
export * from './sharkModel';
export * from './slackIntegrationInfoModel';
export * from './sslTlsSettingModel';
export * from './startVerificationApiModel';
export * from './startVerificationResult';
export * from './tFSIntegrationInfoModel';
export * from './teamApiModelListApiResult';
export * from './teamApiViewModel';
export * from './technologyApiModel';
export * from './technologyListApiResult';
export * from './testScanProfileCredentialsRequestModel';
export * from './threeLeggedFields';
export * from './timezoneApiModel';
export * from './trelloBoard';
export * from './trelloIntegrationInfoModel';
export * from './trelloLabel';
export * from './trelloList';
export * from './trelloMember';
export * from './unfuddleIntegrationInfoModel';
export * from './updateMemberApiModel';
export * from './updateRoleApiModel';
export * from './updateScanNotificationApiModel';
export * from './updateScanPolicySettingModel';
export * from './updateScheduledIncrementalScanApiModel';
export * from './updateScheduledScanApiModel';
export * from './updateScheduledScanModel';
export * from './updateTeamApiModel';
export * from './updateWebsiteApiModel';
export * from './updateWebsiteGroupApiModel';
export * from './urlRewriteExcludedPathModel';
export * from './urlRewriteRuleModel';
export * from './urlRewriteSetting';
export * from './userApiTokenModel';
export * from './userHealthCheckApiModel';
export * from './vcsCommitInfo';
export * from './verifyApiModel';
export * from './versionIssue';
export * from './vulnerabilityClassification';
export * from './vulnerabilityContentApiModel';
export * from './vulnerabilityModel';
export * from './vulnerabilityTemplate';
export * from './vulnerabilityTemplateCvss31Vector';
export * from './vulnerabilityTemplateCvssVector';
export * from './webStorageSetting';
export * from './webhookIntegrationInfoModel';
export * from './websiteApiModel';
export * from './websiteGroupApiModel';
export * from './websiteGroupListApiResult';
export * from './websiteGroupModel';
export * from './websiteListApiResult';
export * from './youTrackIntegrationInfoModel';
export * from './zapierIntegrationInfoModel';

import * as fs from 'fs';

export interface RequestDetailedFile {
    value: Buffer;
    options?: {
        filename?: string;
        contentType?: string;
    }
}

export type RequestFile = string | Buffer | fs.ReadStream | RequestDetailedFile;


import { AccessTokenTableModel } from './accessTokenTableModel';
import { AccountLicenseApiModel } from './accountLicenseApiModel';
import { AdditionalWebsiteModel } from './additionalWebsiteModel';
import { AdditionalWebsitesSettingModel } from './additionalWebsitesSettingModel';
import { AgentGroupApiDeleteModel } from './agentGroupApiDeleteModel';
import { AgentGroupApiModel } from './agentGroupApiModel';
import { AgentGroupApiNewModel } from './agentGroupApiNewModel';
import { AgentGroupApiUpdateModel } from './agentGroupApiUpdateModel';
import { AgentGroupModel } from './agentGroupModel';
import { AgentGroupsListApiResult } from './agentGroupsListApiResult';
import { AgentListApiModel } from './agentListApiModel';
import { AgentListApiResult } from './agentListApiResult';
import { AgentSelectionModel } from './agentSelectionModel';
import { AgentStatusModel } from './agentStatusModel';
import { ApiFileModel } from './apiFileModel';
import { ApiScanStatusModel } from './apiScanStatusModel';
import { AsanaIntegrationInfoModel } from './asanaIntegrationInfoModel';
import { AsanaProject } from './asanaProject';
import { AsanaTag } from './asanaTag';
import { AsanaUser } from './asanaUser';
import { AsanaWorkspace } from './asanaWorkspace';
import { AttackingSettingModel } from './attackingSettingModel';
import { AuthVerificationApiResult } from './authVerificationApiResult';
import { AuthenticationProfileViewModel } from './authenticationProfileViewModel';
import { AuthorizationCodeTableModel } from './authorizationCodeTableModel';
import { AutoCompleteSettingModel } from './autoCompleteSettingModel';
import { AzureDevOpsIntegrationInfoModel } from './azureDevOpsIntegrationInfoModel';
import { BaseResponseApiModel } from './baseResponseApiModel';
import { BaseScanApiModel } from './baseScanApiModel';
import { BasicAuthenticationCredentialApiModel } from './basicAuthenticationCredentialApiModel';
import { BasicAuthenticationCredentialModel } from './basicAuthenticationCredentialModel';
import { BasicAuthenticationSettingApiModel } from './basicAuthenticationSettingApiModel';
import { BasicAuthenticationSettingModel } from './basicAuthenticationSettingModel';
import { BitbucketIntegrationInfoModel } from './bitbucketIntegrationInfoModel';
import { BruteForceSettingModel } from './bruteForceSettingModel';
import { BugzillaIntegrationInfoModel } from './bugzillaIntegrationInfoModel';
import { ClientCertificateAuthenticationApiModel } from './clientCertificateAuthenticationApiModel';
import { ClientCertificateAuthenticationViewModel } from './clientCertificateAuthenticationViewModel';
import { ClubhouseIntegrationInfoModel } from './clubhouseIntegrationInfoModel';
import { ContentTypeModel } from './contentTypeModel';
import { ContentTypeTemplate } from './contentTypeTemplate';
import { CrawlingSettingModel } from './crawlingSettingModel';
import { CsrfSettingModel } from './csrfSettingModel';
import { Custom404SettingModel } from './custom404SettingModel';
import { CustomFieldModel } from './customFieldModel';
import { CustomHttpHeaderModel } from './customHttpHeaderModel';
import { CustomHttpHeaderSetting } from './customHttpHeaderSetting';
import { CustomScriptPageViewModel } from './customScriptPageViewModel';
import { CustomTemplateContentModel } from './customTemplateContentModel';
import { CustomTemplateModel } from './customTemplateModel';
import { CvssMetricModel } from './cvssMetricModel';
import { CvssScoreValue } from './cvssScoreValue';
import { CyberArkVaultIntegrationInfoModel } from './cyberArkVaultIntegrationInfoModel';
import { DeleteAgentModel } from './deleteAgentModel';
import { DeleteScanNotificationApiModel } from './deleteScanNotificationApiModel';
import { DeleteWebsiteApiModel } from './deleteWebsiteApiModel';
import { DeleteWebsiteGroupApiModel } from './deleteWebsiteGroupApiModel';
import { DiscoveryApiModel } from './discoveryApiModel';
import { DiscoveryServiceListApiResult } from './discoveryServiceListApiResult';
import { DiscoverySettingsApiModel } from './discoverySettingsApiModel';
import { EmailPatternSetting } from './emailPatternSetting';
import { ExcludeFilter } from './excludeFilter';
import { ExcludedLinkModel } from './excludedLinkModel';
import { ExcludedUsageTrackerModel } from './excludedUsageTrackerModel';
import { ExtensionSettingModel } from './extensionSettingModel';
import { FileCache } from './fileCache';
import { FogBugzIntegrationInfoModel } from './fogBugzIntegrationInfoModel';
import { FormAuthenticationCustomScript } from './formAuthenticationCustomScript';
import { FormAuthenticationCyberArkVaultSetting } from './formAuthenticationCyberArkVaultSetting';
import { FormAuthenticationHashicorpVaultSetting } from './formAuthenticationHashicorpVaultSetting';
import { FormAuthenticationPersona } from './formAuthenticationPersona';
import { FormAuthenticationSettingApiModel } from './formAuthenticationSettingApiModel';
import { FormAuthenticationSettingModel } from './formAuthenticationSettingModel';
import { FormAuthenticationVerificationApiModel } from './formAuthenticationVerificationApiModel';
import { FormValueSettingModel } from './formValueSettingModel';
import { FreshserviceEntity } from './freshserviceEntity';
import { FreshserviceIntegrationInfoModel } from './freshserviceIntegrationInfoModel';
import { FreshserviceUser } from './freshserviceUser';
import { GitHubIntegrationInfoModel } from './gitHubIntegrationInfoModel';
import { GitLabIntegrationInfoModel } from './gitLabIntegrationInfoModel';
import { HashicorpVaultIntegrationInfoModel } from './hashicorpVaultIntegrationInfoModel';
import { HeaderAuthenticationModel } from './headerAuthenticationModel';
import { HttpRequestSettingModel } from './httpRequestSettingModel';
import { IdNamePair } from './idNamePair';
import { IgnorePatternSettingModel } from './ignorePatternSettingModel';
import { ImportedLinksSetting } from './importedLinksSetting';
import { IncrementalApiModel } from './incrementalApiModel';
import { IntegrationUserMappingItemModel } from './integrationUserMappingItemModel';
import { IntegrationWizardResultModel } from './integrationWizardResultModel';
import { IssueApiModel } from './issueApiModel';
import { IssueApiModelCvssVector } from './issueApiModelCvssVector';
import { IssueApiResult } from './issueApiResult';
import { IssueApiUpdateModel } from './issueApiUpdateModel';
import { IssueHistoryApiModel } from './issueHistoryApiModel';
import { IssueReportFilterApiModel } from './issueReportFilterApiModel';
import { IssueRequestContentParametersApiModel } from './issueRequestContentParametersApiModel';
import { JavaScriptSettingsModel } from './javaScriptSettingsModel';
import { JiraIntegrationInfoModel } from './jiraIntegrationInfoModel';
import { KafkaIntegrationInfoModel } from './kafkaIntegrationInfoModel';
import { KennaIntegrationInfoModel } from './kennaIntegrationInfoModel';
import { LicenseBaseModel } from './licenseBaseModel';
import { LogoutKeywordPatternModel } from './logoutKeywordPatternModel';
import { MattermostIntegrationInfoModel } from './mattermostIntegrationInfoModel';
import { MemberApiModelListApiResult } from './memberApiModelListApiResult';
import { MemberApiViewModel } from './memberApiViewModel';
import { MemberInvitationApiModelListApiResult } from './memberInvitationApiModelListApiResult';
import { MemberInvitationApiViewModel } from './memberInvitationApiViewModel';
import { MicrosoftTeamsIntegrationInfoModel } from './microsoftTeamsIntegrationInfoModel';
import { NameValuePair } from './nameValuePair';
import { NewGroupScanApiModel } from './newGroupScanApiModel';
import { NewMemberApiModel } from './newMemberApiModel';
import { NewMemberInvitationApiModel } from './newMemberInvitationApiModel';
import { NewRoleApiModel } from './newRoleApiModel';
import { NewScanNotificationApiModel } from './newScanNotificationApiModel';
import { NewScanNotificationRecipientApiModel } from './newScanNotificationRecipientApiModel';
import { NewScanPolicySettingModel } from './newScanPolicySettingModel';
import { NewScanTaskApiModel } from './newScanTaskApiModel';
import { NewScanTaskWithProfileApiModel } from './newScanTaskWithProfileApiModel';
import { NewScheduledIncrementalScanApiModel } from './newScheduledIncrementalScanApiModel';
import { NewScheduledScanApiModel } from './newScheduledScanApiModel';
import { NewScheduledWithProfileApiModel } from './newScheduledWithProfileApiModel';
import { NewTeamApiModel } from './newTeamApiModel';
import { NewWebsiteApiModel } from './newWebsiteApiModel';
import { NewWebsiteGroupApiModel } from './newWebsiteGroupApiModel';
import { NotificationIntegrationCustomFieldModel } from './notificationIntegrationCustomFieldModel';
import { NotificationPriorityPair } from './notificationPriorityPair';
import { OAuth2SettingApiModel } from './oAuth2SettingApiModel';
import { OAuth2SettingEndPointModel } from './oAuth2SettingEndPointModel';
import { OAuth2SettingEndpoint } from './oAuth2SettingEndpoint';
import { OAuth2SettingModel } from './oAuth2SettingModel';
import { OtpSettings } from './otpSettings';
import { OutsiderRecipient } from './outsiderRecipient';
import { PagerDutyIntegrationInfoModel } from './pagerDutyIntegrationInfoModel';
import { PciScanTaskViewModel } from './pciScanTaskViewModel';
import { PermissionApiModel } from './permissionApiModel';
import { PivotalTrackerIntegrationInfoModel } from './pivotalTrackerIntegrationInfoModel';
import { PreRequestScriptSettingModel } from './preRequestScriptSettingModel';
import { ProxySettingsModel } from './proxySettingsModel';
import { RedmineIntegrationInfoModel } from './redmineIntegrationInfoModel';
import { ReducedMemberApiViewModel } from './reducedMemberApiViewModel';
import { ReducedScanTaskProfile } from './reducedScanTaskProfile';
import { ReducedTeamApiViewModel } from './reducedTeamApiViewModel';
import { ResponseFields } from './responseFields';
import { RoleApiModelListApiResult } from './roleApiModelListApiResult';
import { RoleApiViewModel } from './roleApiViewModel';
import { RoleWebsiteGroupMappingApiModel } from './roleWebsiteGroupMappingApiModel';
import { RoleWebsiteGroupMappingApiViewModel } from './roleWebsiteGroupMappingApiViewModel';
import { SaveScanProfileApiModel } from './saveScanProfileApiModel';
import { ScanCustomReportApiModel } from './scanCustomReportApiModel';
import { ScanNotificationApiModel } from './scanNotificationApiModel';
import { ScanNotificationIntegrationViewModel } from './scanNotificationIntegrationViewModel';
import { ScanNotificationListApiResult } from './scanNotificationListApiResult';
import { ScanNotificationRecipientApiModel } from './scanNotificationRecipientApiModel';
import { ScanNotificationRecipientUserApiModel } from './scanNotificationRecipientUserApiModel';
import { ScanNotificationScanTaskGroupApiModel } from './scanNotificationScanTaskGroupApiModel';
import { ScanPolicyListApiResult } from './scanPolicyListApiResult';
import { ScanPolicyOptimizerOptions } from './scanPolicyOptimizerOptions';
import { ScanPolicyPatternModel } from './scanPolicyPatternModel';
import { ScanPolicySettingApiModel } from './scanPolicySettingApiModel';
import { ScanPolicySettingItemApiModel } from './scanPolicySettingItemApiModel';
import { ScanReportApiModel } from './scanReportApiModel';
import { ScanTaskListApiResult } from './scanTaskListApiResult';
import { ScanTaskModel } from './scanTaskModel';
import { ScanTimeWindowItemModel } from './scanTimeWindowItemModel';
import { ScanTimeWindowItemViewModel } from './scanTimeWindowItemViewModel';
import { ScanTimeWindowModel } from './scanTimeWindowModel';
import { ScanTimeWindowViewModel } from './scanTimeWindowViewModel';
import { ScheduledScanListApiResult } from './scheduledScanListApiResult';
import { ScheduledScanModel } from './scheduledScanModel';
import { ScheduledScanRecurrenceApiModel } from './scheduledScanRecurrenceApiModel';
import { ScheduledScanRecurrenceViewModel } from './scheduledScanRecurrenceViewModel';
import { ScopeSetting } from './scopeSetting';
import { ScopeSettingModel } from './scopeSettingModel';
import { SecurityCheckGroupModel } from './securityCheckGroupModel';
import { SecurityCheckGroupParentModel } from './securityCheckGroupParentModel';
import { SecurityCheckSetting } from './securityCheckSetting';
import { SelectOptionModel } from './selectOptionModel';
import { SendVerificationEmailModel } from './sendVerificationEmailModel';
import { SensitiveKeywordSettingModel } from './sensitiveKeywordSettingModel';
import { ServiceNowIntegrationInfoModel } from './serviceNowIntegrationInfoModel';
import { SharkModel } from './sharkModel';
import { SlackIntegrationInfoModel } from './slackIntegrationInfoModel';
import { SslTlsSettingModel } from './sslTlsSettingModel';
import { StartVerificationApiModel } from './startVerificationApiModel';
import { StartVerificationResult } from './startVerificationResult';
import { TFSIntegrationInfoModel } from './tFSIntegrationInfoModel';
import { TeamApiModelListApiResult } from './teamApiModelListApiResult';
import { TeamApiViewModel } from './teamApiViewModel';
import { TechnologyApiModel } from './technologyApiModel';
import { TechnologyListApiResult } from './technologyListApiResult';
import { TestScanProfileCredentialsRequestModel } from './testScanProfileCredentialsRequestModel';
import { ThreeLeggedFields } from './threeLeggedFields';
import { TimezoneApiModel } from './timezoneApiModel';
import { TrelloBoard } from './trelloBoard';
import { TrelloIntegrationInfoModel } from './trelloIntegrationInfoModel';
import { TrelloLabel } from './trelloLabel';
import { TrelloList } from './trelloList';
import { TrelloMember } from './trelloMember';
import { UnfuddleIntegrationInfoModel } from './unfuddleIntegrationInfoModel';
import { UpdateMemberApiModel } from './updateMemberApiModel';
import { UpdateRoleApiModel } from './updateRoleApiModel';
import { UpdateScanNotificationApiModel } from './updateScanNotificationApiModel';
import { UpdateScanPolicySettingModel } from './updateScanPolicySettingModel';
import { UpdateScheduledIncrementalScanApiModel } from './updateScheduledIncrementalScanApiModel';
import { UpdateScheduledScanApiModel } from './updateScheduledScanApiModel';
import { UpdateScheduledScanModel } from './updateScheduledScanModel';
import { UpdateTeamApiModel } from './updateTeamApiModel';
import { UpdateWebsiteApiModel } from './updateWebsiteApiModel';
import { UpdateWebsiteGroupApiModel } from './updateWebsiteGroupApiModel';
import { UrlRewriteExcludedPathModel } from './urlRewriteExcludedPathModel';
import { UrlRewriteRuleModel } from './urlRewriteRuleModel';
import { UrlRewriteSetting } from './urlRewriteSetting';
import { UserApiTokenModel } from './userApiTokenModel';
import { UserHealthCheckApiModel } from './userHealthCheckApiModel';
import { VcsCommitInfo } from './vcsCommitInfo';
import { VerifyApiModel } from './verifyApiModel';
import { VersionIssue } from './versionIssue';
import { VulnerabilityClassification } from './vulnerabilityClassification';
import { VulnerabilityContentApiModel } from './vulnerabilityContentApiModel';
import { VulnerabilityModel } from './vulnerabilityModel';
import { VulnerabilityTemplate } from './vulnerabilityTemplate';
import { VulnerabilityTemplateCvss31Vector } from './vulnerabilityTemplateCvss31Vector';
import { VulnerabilityTemplateCvssVector } from './vulnerabilityTemplateCvssVector';
import { WebStorageSetting } from './webStorageSetting';
import { WebhookIntegrationInfoModel } from './webhookIntegrationInfoModel';
import { WebsiteApiModel } from './websiteApiModel';
import { WebsiteGroupApiModel } from './websiteGroupApiModel';
import { WebsiteGroupListApiResult } from './websiteGroupListApiResult';
import { WebsiteGroupModel } from './websiteGroupModel';
import { WebsiteListApiResult } from './websiteListApiResult';
import { YouTrackIntegrationInfoModel } from './youTrackIntegrationInfoModel';
import { ZapierIntegrationInfoModel } from './zapierIntegrationInfoModel';

/* tslint:disable:no-unused-variable */
let primitives = [
                    "string",
                    "boolean",
                    "double",
                    "integer",
                    "long",
                    "float",
                    "number",
                    "any"
                 ];

let enumsMap: {[index: string]: any} = {
        "AgentListApiModel.StateEnum": AgentListApiModel.StateEnum,
        "ApiFileModel.ImporterTypeEnum": ApiFileModel.ImporterTypeEnum,
        "ApiScanStatusModel.StateEnum": ApiScanStatusModel.StateEnum,
        "AsanaIntegrationInfoModel.TypeEnum": AsanaIntegrationInfoModel.TypeEnum,
        "AuthVerificationApiResult.LogoutSignatureTypeEnum": AuthVerificationApiResult.LogoutSignatureTypeEnum,
        "AzureDevOpsIntegrationInfoModel.TypeEnum": AzureDevOpsIntegrationInfoModel.TypeEnum,
        "BasicAuthenticationCredentialApiModel.AuthenticationTypeEnum": BasicAuthenticationCredentialApiModel.AuthenticationTypeEnum,
        "BasicAuthenticationCredentialModel.AuthenticationTypeEnum": BasicAuthenticationCredentialModel.AuthenticationTypeEnum,
        "BitbucketIntegrationInfoModel.TypeEnum": BitbucketIntegrationInfoModel.TypeEnum,
        "BugzillaIntegrationInfoModel.TypeEnum": BugzillaIntegrationInfoModel.TypeEnum,
        "ClubhouseIntegrationInfoModel.ClubhouseStoryTypeEnum": ClubhouseIntegrationInfoModel.ClubhouseStoryTypeEnum,
        "ClubhouseIntegrationInfoModel.TypeEnum": ClubhouseIntegrationInfoModel.TypeEnum,
        "CustomHttpHeaderSetting.AttackModeEnum": CustomHttpHeaderSetting.AttackModeEnum,
        "CvssScoreValue.SeverityEnum": CvssScoreValue.SeverityEnum,
        "CyberArkVaultIntegrationInfoModel.TypeEnum": CyberArkVaultIntegrationInfoModel.TypeEnum,
        "DiscoveryApiModel.StatusEnum": DiscoveryApiModel.StatusEnum,
        "ExtensionSettingModel.AttackOptionEnum": ExtensionSettingModel.AttackOptionEnum,
        "ExtensionSettingModel.CrawlOptionEnum": ExtensionSettingModel.CrawlOptionEnum,
        "FileCache.ImporterTypeEnum": FileCache.ImporterTypeEnum,
        "FogBugzIntegrationInfoModel.TypeEnum": FogBugzIntegrationInfoModel.TypeEnum,
        "FormAuthenticationHashicorpVaultSetting.VersionEnum": FormAuthenticationHashicorpVaultSetting.VersionEnum,
        "FormAuthenticationPersona.OtpTypeEnum": FormAuthenticationPersona.OtpTypeEnum,
        "FormAuthenticationPersona.DigitEnum": FormAuthenticationPersona.DigitEnum,
        "FormAuthenticationPersona.AlgorithmEnum": FormAuthenticationPersona.AlgorithmEnum,
        "FormAuthenticationPersona.FormAuthTypeEnum": FormAuthenticationPersona.FormAuthTypeEnum,
        "FormAuthenticationPersona.VersionEnum": FormAuthenticationPersona.VersionEnum,
        "FormAuthenticationSettingApiModel.FormAuthTypeEnum": FormAuthenticationSettingApiModel.FormAuthTypeEnum,
        "FormValueSettingModel.MatchEnum": FormValueSettingModel.MatchEnum,
        "FormValueSettingModel.MatchTargetEnum": FormValueSettingModel.MatchTargetEnum,
        "FormValueSettingModel.MatchTargetValueEnum": FormValueSettingModel.MatchTargetValueEnum,
        "FreshserviceIntegrationInfoModel.TypeEnum": FreshserviceIntegrationInfoModel.TypeEnum,
        "GitHubIntegrationInfoModel.TypeEnum": GitHubIntegrationInfoModel.TypeEnum,
        "GitLabIntegrationInfoModel.TypeEnum": GitLabIntegrationInfoModel.TypeEnum,
        "HashicorpVaultIntegrationInfoModel.TypeEnum": HashicorpVaultIntegrationInfoModel.TypeEnum,
        "IgnorePatternSettingModel.ParameterTypeEnum": IgnorePatternSettingModel.ParameterTypeEnum,
        "IntegrationUserMappingItemModel.IntegrationSystemEnum": IntegrationUserMappingItemModel.IntegrationSystemEnum,
        "IntegrationUserMappingItemModel.ResultEnum": IntegrationUserMappingItemModel.ResultEnum,
        "IssueApiModel.SeverityEnum": IssueApiModel.SeverityEnum,
        "IssueApiModel.TypeEnum": IssueApiModel.TypeEnum,
        "IssueReportFilterApiModel.CsvSeparatorEnum": IssueReportFilterApiModel.CsvSeparatorEnum,
        "IssueReportFilterApiModel.SeverityEnum": IssueReportFilterApiModel.SeverityEnum,
        "IssueRequestContentParametersApiModel.InputTypeEnum": IssueRequestContentParametersApiModel.InputTypeEnum,
        "JiraIntegrationInfoModel.ReopenStatusJiraEnum": JiraIntegrationInfoModel.ReopenStatusJiraEnum,
        "JiraIntegrationInfoModel.TypeEnum": JiraIntegrationInfoModel.TypeEnum,
        "JiraIntegrationInfoModel.TemplateTypeEnum": JiraIntegrationInfoModel.TemplateTypeEnum,
        "JiraIntegrationInfoModel.EpicSelectionTypeEnum": JiraIntegrationInfoModel.EpicSelectionTypeEnum,
        "KafkaIntegrationInfoModel.DataSerializationEnum": KafkaIntegrationInfoModel.DataSerializationEnum,
        "KafkaIntegrationInfoModel.TypeEnum": KafkaIntegrationInfoModel.TypeEnum,
        "KennaIntegrationInfoModel.AssetApplicationIdentifierTypeEnum": KennaIntegrationInfoModel.AssetApplicationIdentifierTypeEnum,
        "KennaIntegrationInfoModel.TypeEnum": KennaIntegrationInfoModel.TypeEnum,
        "MattermostIntegrationInfoModel.TypeEnum": MattermostIntegrationInfoModel.TypeEnum,
        "MemberApiViewModel.StateEnum": MemberApiViewModel.StateEnum,
        "MicrosoftTeamsIntegrationInfoModel.TypeEnum": MicrosoftTeamsIntegrationInfoModel.TypeEnum,
        "NewGroupScanApiModel.AuthenticationProfileOptionEnum": NewGroupScanApiModel.AuthenticationProfileOptionEnum,
        "NewScanNotificationApiModel.EventEnum": NewScanNotificationApiModel.EventEnum,
        "NewScanNotificationApiModel.SeverityEnum": NewScanNotificationApiModel.SeverityEnum,
        "NewScanNotificationApiModel.StateEnum": NewScanNotificationApiModel.StateEnum,
        "NewScanNotificationApiModel.ScopeEnum": NewScanNotificationApiModel.ScopeEnum,
        "NewScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum": NewScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum,
        "NewScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum": NewScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum,
        "NewScanTaskApiModel.DisallowedHttpMethodsEnum": NewScanTaskApiModel.DisallowedHttpMethodsEnum,
        "NewScanTaskApiModel.AuthenticationProfileOptionEnum": NewScanTaskApiModel.AuthenticationProfileOptionEnum,
        "NewScanTaskApiModel.ScopeEnum": NewScanTaskApiModel.ScopeEnum,
        "NewScanTaskApiModel.UrlRewriteModeEnum": NewScanTaskApiModel.UrlRewriteModeEnum,
        "NewScheduledIncrementalScanApiModel.ScheduleRunTypeEnum": NewScheduledIncrementalScanApiModel.ScheduleRunTypeEnum,
        "NewScheduledScanApiModel.ScheduleRunTypeEnum": NewScheduledScanApiModel.ScheduleRunTypeEnum,
        "NewScheduledScanApiModel.DisallowedHttpMethodsEnum": NewScheduledScanApiModel.DisallowedHttpMethodsEnum,
        "NewScheduledScanApiModel.AuthenticationProfileOptionEnum": NewScheduledScanApiModel.AuthenticationProfileOptionEnum,
        "NewScheduledScanApiModel.ScopeEnum": NewScheduledScanApiModel.ScopeEnum,
        "NewScheduledScanApiModel.UrlRewriteModeEnum": NewScheduledScanApiModel.UrlRewriteModeEnum,
        "NewScheduledWithProfileApiModel.ScheduleRunTypeEnum": NewScheduledWithProfileApiModel.ScheduleRunTypeEnum,
        "NewWebsiteApiModel.AgentModeEnum": NewWebsiteApiModel.AgentModeEnum,
        "NewWebsiteApiModel.LicenseTypeEnum": NewWebsiteApiModel.LicenseTypeEnum,
        "NotificationIntegrationCustomFieldModel.InputTypeEnum": NotificationIntegrationCustomFieldModel.InputTypeEnum,
        "OAuth2SettingApiModel.FlowTypeEnum": OAuth2SettingApiModel.FlowTypeEnum,
        "OAuth2SettingApiModel.AuthenticationTypeEnum": OAuth2SettingApiModel.AuthenticationTypeEnum,
        "OAuth2SettingModel.SelectedFlowTypeEnum": OAuth2SettingModel.SelectedFlowTypeEnum,
        "OAuth2SettingModel.SelectedAuthenticationTypeEnum": OAuth2SettingModel.SelectedAuthenticationTypeEnum,
        "OtpSettings.OtpTypeEnum": OtpSettings.OtpTypeEnum,
        "OtpSettings.DigitEnum": OtpSettings.DigitEnum,
        "OtpSettings.AlgorithmEnum": OtpSettings.AlgorithmEnum,
        "PagerDutyIntegrationInfoModel.ServiceTypeEnum": PagerDutyIntegrationInfoModel.ServiceTypeEnum,
        "PagerDutyIntegrationInfoModel.TypeEnum": PagerDutyIntegrationInfoModel.TypeEnum,
        "PagerDutyIntegrationInfoModel.UrgencyEnum": PagerDutyIntegrationInfoModel.UrgencyEnum,
        "PciScanTaskViewModel.ScanStateEnum": PciScanTaskViewModel.ScanStateEnum,
        "PciScanTaskViewModel.ComplianceStatusEnum": PciScanTaskViewModel.ComplianceStatusEnum,
        "PivotalTrackerIntegrationInfoModel.TypeEnum": PivotalTrackerIntegrationInfoModel.TypeEnum,
        "PivotalTrackerIntegrationInfoModel.StoryTypeEnum": PivotalTrackerIntegrationInfoModel.StoryTypeEnum,
        "RedmineIntegrationInfoModel.TypeEnum": RedmineIntegrationInfoModel.TypeEnum,
        "SaveScanProfileApiModel.CreateTypeEnum": SaveScanProfileApiModel.CreateTypeEnum,
        "SaveScanProfileApiModel.DisallowedHttpMethodsEnum": SaveScanProfileApiModel.DisallowedHttpMethodsEnum,
        "SaveScanProfileApiModel.AuthenticationProfileOptionEnum": SaveScanProfileApiModel.AuthenticationProfileOptionEnum,
        "SaveScanProfileApiModel.ScopeEnum": SaveScanProfileApiModel.ScopeEnum,
        "SaveScanProfileApiModel.UrlRewriteModeEnum": SaveScanProfileApiModel.UrlRewriteModeEnum,
        "ScanCustomReportApiModel.ReportFormatEnum": ScanCustomReportApiModel.ReportFormatEnum,
        "ScanNotificationApiModel.EventEnum": ScanNotificationApiModel.EventEnum,
        "ScanNotificationApiModel.SeverityEnum": ScanNotificationApiModel.SeverityEnum,
        "ScanNotificationApiModel.StateEnum": ScanNotificationApiModel.StateEnum,
        "ScanNotificationApiModel.ScopeEnum": ScanNotificationApiModel.ScopeEnum,
        "ScanNotificationIntegrationViewModel.CategoryEnum": ScanNotificationIntegrationViewModel.CategoryEnum,
        "ScanNotificationIntegrationViewModel.TypeEnum": ScanNotificationIntegrationViewModel.TypeEnum,
        "ScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum": ScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum,
        "ScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum": ScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum,
        "ScanPolicyOptimizerOptions.AppServerEnum": ScanPolicyOptimizerOptions.AppServerEnum,
        "ScanPolicyOptimizerOptions.DatabaseServerEnum": ScanPolicyOptimizerOptions.DatabaseServerEnum,
        "ScanPolicyOptimizerOptions.DomParserPresetEnum": ScanPolicyOptimizerOptions.DomParserPresetEnum,
        "ScanPolicyOptimizerOptions.OperatingSystemEnum": ScanPolicyOptimizerOptions.OperatingSystemEnum,
        "ScanPolicyOptimizerOptions.SuggestionStatusEnum": ScanPolicyOptimizerOptions.SuggestionStatusEnum,
        "ScanPolicyOptimizerOptions.WebServerEnum": ScanPolicyOptimizerOptions.WebServerEnum,
        "ScanReportApiModel.ContentFormatEnum": ScanReportApiModel.ContentFormatEnum,
        "ScanReportApiModel.FormatEnum": ScanReportApiModel.FormatEnum,
        "ScanReportApiModel.TypeEnum": ScanReportApiModel.TypeEnum,
        "ScanTaskModel.AuthenticationProfileOptionEnum": ScanTaskModel.AuthenticationProfileOptionEnum,
        "ScanTaskModel.ScopeEnum": ScanTaskModel.ScopeEnum,
        "ScanTaskModel.UrlRewriteModeEnum": ScanTaskModel.UrlRewriteModeEnum,
        "ScanTaskModel.FailureReasonEnum": ScanTaskModel.FailureReasonEnum,
        "ScanTaskModel.GlobalThreatLevelEnum": ScanTaskModel.GlobalThreatLevelEnum,
        "ScanTaskModel.PhaseEnum": ScanTaskModel.PhaseEnum,
        "ScanTaskModel.ScanTypeEnum": ScanTaskModel.ScanTypeEnum,
        "ScanTaskModel.StateEnum": ScanTaskModel.StateEnum,
        "ScanTaskModel.ThreatLevelEnum": ScanTaskModel.ThreatLevelEnum,
        "ScanTimeWindowItemModel.DayEnum": ScanTimeWindowItemModel.DayEnum,
        "ScanTimeWindowItemViewModel.DayEnum": ScanTimeWindowItemViewModel.DayEnum,
        "ScanTimeWindowViewModel.ScanCreateTypeEnum": ScanTimeWindowViewModel.ScanCreateTypeEnum,
        "ScheduledScanModel.LastExecutionStatusEnum": ScheduledScanModel.LastExecutionStatusEnum,
        "ScheduledScanModel.ScanTypeEnum": ScheduledScanModel.ScanTypeEnum,
        "ScheduledScanModel.ScheduleRunTypeEnum": ScheduledScanModel.ScheduleRunTypeEnum,
        "ScheduledScanModel.CustomScriptTemplateTypeEnum": ScheduledScanModel.CustomScriptTemplateTypeEnum,
        "ScheduledScanModel.CreateTypeEnum": ScheduledScanModel.CreateTypeEnum,
        "ScheduledScanRecurrenceApiModel.RepeatTypeEnum": ScheduledScanRecurrenceApiModel.RepeatTypeEnum,
        "ScheduledScanRecurrenceApiModel.EndingTypeEnum": ScheduledScanRecurrenceApiModel.EndingTypeEnum,
        "ScheduledScanRecurrenceApiModel.DaysOfWeekEnum": ScheduledScanRecurrenceApiModel.DaysOfWeekEnum,
        "ScheduledScanRecurrenceApiModel.MonthsOfYearEnum": ScheduledScanRecurrenceApiModel.MonthsOfYearEnum,
        "ScheduledScanRecurrenceApiModel.OrdinalEnum": ScheduledScanRecurrenceApiModel.OrdinalEnum,
        "ScheduledScanRecurrenceApiModel.DayOfWeekEnum": ScheduledScanRecurrenceApiModel.DayOfWeekEnum,
        "ScheduledScanRecurrenceViewModel.RepeatTypeEnum": ScheduledScanRecurrenceViewModel.RepeatTypeEnum,
        "ScheduledScanRecurrenceViewModel.EndingTypeEnum": ScheduledScanRecurrenceViewModel.EndingTypeEnum,
        "ScheduledScanRecurrenceViewModel.DaysOfWeekEnum": ScheduledScanRecurrenceViewModel.DaysOfWeekEnum,
        "ScheduledScanRecurrenceViewModel.MonthsOfYearEnum": ScheduledScanRecurrenceViewModel.MonthsOfYearEnum,
        "ScheduledScanRecurrenceViewModel.OrdinalEnum": ScheduledScanRecurrenceViewModel.OrdinalEnum,
        "ScheduledScanRecurrenceViewModel.DayOfWeekEnum": ScheduledScanRecurrenceViewModel.DayOfWeekEnum,
        "ScopeSetting.DisallowedHttpMethodsEnum": ScopeSetting.DisallowedHttpMethodsEnum,
        "ScopeSetting.ScopeEnum": ScopeSetting.ScopeEnum,
        "SecurityCheckGroupModel.TypeEnum": SecurityCheckGroupModel.TypeEnum,
        "SecurityCheckGroupModel.EngineGroupEnum": SecurityCheckGroupModel.EngineGroupEnum,
        "ServiceNowIntegrationInfoModel.ServiceNowCategoryTypesEnum": ServiceNowIntegrationInfoModel.ServiceNowCategoryTypesEnum,
        "ServiceNowIntegrationInfoModel.ServiceNowReopenCategoryTypeEnum": ServiceNowIntegrationInfoModel.ServiceNowReopenCategoryTypeEnum,
        "ServiceNowIntegrationInfoModel.ServiceNowOnHoldReasonTypeEnum": ServiceNowIntegrationInfoModel.ServiceNowOnHoldReasonTypeEnum,
        "ServiceNowIntegrationInfoModel.ResolvedStatusServiceNowEnum": ServiceNowIntegrationInfoModel.ResolvedStatusServiceNowEnum,
        "ServiceNowIntegrationInfoModel.TypeEnum": ServiceNowIntegrationInfoModel.TypeEnum,
        "ServiceNowIntegrationInfoModel.TemplateTypeEnum": ServiceNowIntegrationInfoModel.TemplateTypeEnum,
        "SharkModel.SharkPlatformTypeEnum": SharkModel.SharkPlatformTypeEnum,
        "SlackIntegrationInfoModel.TypeEnum": SlackIntegrationInfoModel.TypeEnum,
        "SslTlsSettingModel.ExternalDomainInvalidCertificateActionEnum": SslTlsSettingModel.ExternalDomainInvalidCertificateActionEnum,
        "SslTlsSettingModel.TargetUrlInvalidCertificateActionEnum": SslTlsSettingModel.TargetUrlInvalidCertificateActionEnum,
        "StartVerificationApiModel.VerificationMethodEnum": StartVerificationApiModel.VerificationMethodEnum,
        "StartVerificationResult.VerifyOwnershipResultEnum": StartVerificationResult.VerifyOwnershipResultEnum,
        "TFSIntegrationInfoModel.TypeEnum": TFSIntegrationInfoModel.TypeEnum,
        "TrelloIntegrationInfoModel.TypeEnum": TrelloIntegrationInfoModel.TypeEnum,
        "UnfuddleIntegrationInfoModel.TypeEnum": UnfuddleIntegrationInfoModel.TypeEnum,
        "UpdateScanNotificationApiModel.EventEnum": UpdateScanNotificationApiModel.EventEnum,
        "UpdateScanNotificationApiModel.SeverityEnum": UpdateScanNotificationApiModel.SeverityEnum,
        "UpdateScanNotificationApiModel.StateEnum": UpdateScanNotificationApiModel.StateEnum,
        "UpdateScanNotificationApiModel.ScopeEnum": UpdateScanNotificationApiModel.ScopeEnum,
        "UpdateScheduledIncrementalScanApiModel.ScheduleRunTypeEnum": UpdateScheduledIncrementalScanApiModel.ScheduleRunTypeEnum,
        "UpdateScheduledScanApiModel.ScheduleRunTypeEnum": UpdateScheduledScanApiModel.ScheduleRunTypeEnum,
        "UpdateScheduledScanApiModel.DisallowedHttpMethodsEnum": UpdateScheduledScanApiModel.DisallowedHttpMethodsEnum,
        "UpdateScheduledScanApiModel.AuthenticationProfileOptionEnum": UpdateScheduledScanApiModel.AuthenticationProfileOptionEnum,
        "UpdateScheduledScanApiModel.ScopeEnum": UpdateScheduledScanApiModel.ScopeEnum,
        "UpdateScheduledScanApiModel.UrlRewriteModeEnum": UpdateScheduledScanApiModel.UrlRewriteModeEnum,
        "UpdateScheduledScanModel.ScanTypeEnum": UpdateScheduledScanModel.ScanTypeEnum,
        "UpdateScheduledScanModel.ScheduleRunTypeEnum": UpdateScheduledScanModel.ScheduleRunTypeEnum,
        "UpdateScheduledScanModel.CustomScriptTemplateTypeEnum": UpdateScheduledScanModel.CustomScriptTemplateTypeEnum,
        "UpdateScheduledScanModel.CreateTypeEnum": UpdateScheduledScanModel.CreateTypeEnum,
        "UpdateWebsiteApiModel.DefaultProtocolEnum": UpdateWebsiteApiModel.DefaultProtocolEnum,
        "UpdateWebsiteApiModel.AgentModeEnum": UpdateWebsiteApiModel.AgentModeEnum,
        "UpdateWebsiteApiModel.LicenseTypeEnum": UpdateWebsiteApiModel.LicenseTypeEnum,
        "UrlRewriteSetting.UrlRewriteModeEnum": UrlRewriteSetting.UrlRewriteModeEnum,
        "VcsCommitInfo.IntegrationSystemEnum": VcsCommitInfo.IntegrationSystemEnum,
        "VerifyApiModel.VerificationMethodEnum": VerifyApiModel.VerificationMethodEnum,
        "VersionIssue.SeverityEnum": VersionIssue.SeverityEnum,
        "VulnerabilityModel.TypeEnum": VulnerabilityModel.TypeEnum,
        "VulnerabilityTemplate.TypeEnum": VulnerabilityTemplate.TypeEnum,
        "VulnerabilityTemplate.SeverityEnum": VulnerabilityTemplate.SeverityEnum,
        "VulnerabilityTemplate.OrderEnum": VulnerabilityTemplate.OrderEnum,
        "WebStorageSetting.TypeEnum": WebStorageSetting.TypeEnum,
        "WebhookIntegrationInfoModel.HttpMethodTypeEnum": WebhookIntegrationInfoModel.HttpMethodTypeEnum,
        "WebhookIntegrationInfoModel.ParameterTypeEnum": WebhookIntegrationInfoModel.ParameterTypeEnum,
        "WebhookIntegrationInfoModel.TypeEnum": WebhookIntegrationInfoModel.TypeEnum,
        "WebsiteApiModel.LicenseTypeEnum": WebsiteApiModel.LicenseTypeEnum,
        "WebsiteApiModel.AgentModeEnum": WebsiteApiModel.AgentModeEnum,
        "YouTrackIntegrationInfoModel.TypeEnum": YouTrackIntegrationInfoModel.TypeEnum,
        "ZapierIntegrationInfoModel.TypeEnum": ZapierIntegrationInfoModel.TypeEnum,
}

let typeMap: {[index: string]: any} = {
    "AccessTokenTableModel": AccessTokenTableModel,
    "AccountLicenseApiModel": AccountLicenseApiModel,
    "AdditionalWebsiteModel": AdditionalWebsiteModel,
    "AdditionalWebsitesSettingModel": AdditionalWebsitesSettingModel,
    "AgentGroupApiDeleteModel": AgentGroupApiDeleteModel,
    "AgentGroupApiModel": AgentGroupApiModel,
    "AgentGroupApiNewModel": AgentGroupApiNewModel,
    "AgentGroupApiUpdateModel": AgentGroupApiUpdateModel,
    "AgentGroupModel": AgentGroupModel,
    "AgentGroupsListApiResult": AgentGroupsListApiResult,
    "AgentListApiModel": AgentListApiModel,
    "AgentListApiResult": AgentListApiResult,
    "AgentSelectionModel": AgentSelectionModel,
    "AgentStatusModel": AgentStatusModel,
    "ApiFileModel": ApiFileModel,
    "ApiScanStatusModel": ApiScanStatusModel,
    "AsanaIntegrationInfoModel": AsanaIntegrationInfoModel,
    "AsanaProject": AsanaProject,
    "AsanaTag": AsanaTag,
    "AsanaUser": AsanaUser,
    "AsanaWorkspace": AsanaWorkspace,
    "AttackingSettingModel": AttackingSettingModel,
    "AuthVerificationApiResult": AuthVerificationApiResult,
    "AuthenticationProfileViewModel": AuthenticationProfileViewModel,
    "AuthorizationCodeTableModel": AuthorizationCodeTableModel,
    "AutoCompleteSettingModel": AutoCompleteSettingModel,
    "AzureDevOpsIntegrationInfoModel": AzureDevOpsIntegrationInfoModel,
    "BaseResponseApiModel": BaseResponseApiModel,
    "BaseScanApiModel": BaseScanApiModel,
    "BasicAuthenticationCredentialApiModel": BasicAuthenticationCredentialApiModel,
    "BasicAuthenticationCredentialModel": BasicAuthenticationCredentialModel,
    "BasicAuthenticationSettingApiModel": BasicAuthenticationSettingApiModel,
    "BasicAuthenticationSettingModel": BasicAuthenticationSettingModel,
    "BitbucketIntegrationInfoModel": BitbucketIntegrationInfoModel,
    "BruteForceSettingModel": BruteForceSettingModel,
    "BugzillaIntegrationInfoModel": BugzillaIntegrationInfoModel,
    "ClientCertificateAuthenticationApiModel": ClientCertificateAuthenticationApiModel,
    "ClientCertificateAuthenticationViewModel": ClientCertificateAuthenticationViewModel,
    "ClubhouseIntegrationInfoModel": ClubhouseIntegrationInfoModel,
    "ContentTypeModel": ContentTypeModel,
    "ContentTypeTemplate": ContentTypeTemplate,
    "CrawlingSettingModel": CrawlingSettingModel,
    "CsrfSettingModel": CsrfSettingModel,
    "Custom404SettingModel": Custom404SettingModel,
    "CustomFieldModel": CustomFieldModel,
    "CustomHttpHeaderModel": CustomHttpHeaderModel,
    "CustomHttpHeaderSetting": CustomHttpHeaderSetting,
    "CustomScriptPageViewModel": CustomScriptPageViewModel,
    "CustomTemplateContentModel": CustomTemplateContentModel,
    "CustomTemplateModel": CustomTemplateModel,
    "CvssMetricModel": CvssMetricModel,
    "CvssScoreValue": CvssScoreValue,
    "CyberArkVaultIntegrationInfoModel": CyberArkVaultIntegrationInfoModel,
    "DeleteAgentModel": DeleteAgentModel,
    "DeleteScanNotificationApiModel": DeleteScanNotificationApiModel,
    "DeleteWebsiteApiModel": DeleteWebsiteApiModel,
    "DeleteWebsiteGroupApiModel": DeleteWebsiteGroupApiModel,
    "DiscoveryApiModel": DiscoveryApiModel,
    "DiscoveryServiceListApiResult": DiscoveryServiceListApiResult,
    "DiscoverySettingsApiModel": DiscoverySettingsApiModel,
    "EmailPatternSetting": EmailPatternSetting,
    "ExcludeFilter": ExcludeFilter,
    "ExcludedLinkModel": ExcludedLinkModel,
    "ExcludedUsageTrackerModel": ExcludedUsageTrackerModel,
    "ExtensionSettingModel": ExtensionSettingModel,
    "FileCache": FileCache,
    "FogBugzIntegrationInfoModel": FogBugzIntegrationInfoModel,
    "FormAuthenticationCustomScript": FormAuthenticationCustomScript,
    "FormAuthenticationCyberArkVaultSetting": FormAuthenticationCyberArkVaultSetting,
    "FormAuthenticationHashicorpVaultSetting": FormAuthenticationHashicorpVaultSetting,
    "FormAuthenticationPersona": FormAuthenticationPersona,
    "FormAuthenticationSettingApiModel": FormAuthenticationSettingApiModel,
    "FormAuthenticationSettingModel": FormAuthenticationSettingModel,
    "FormAuthenticationVerificationApiModel": FormAuthenticationVerificationApiModel,
    "FormValueSettingModel": FormValueSettingModel,
    "FreshserviceEntity": FreshserviceEntity,
    "FreshserviceIntegrationInfoModel": FreshserviceIntegrationInfoModel,
    "FreshserviceUser": FreshserviceUser,
    "GitHubIntegrationInfoModel": GitHubIntegrationInfoModel,
    "GitLabIntegrationInfoModel": GitLabIntegrationInfoModel,
    "HashicorpVaultIntegrationInfoModel": HashicorpVaultIntegrationInfoModel,
    "HeaderAuthenticationModel": HeaderAuthenticationModel,
    "HttpRequestSettingModel": HttpRequestSettingModel,
    "IdNamePair": IdNamePair,
    "IgnorePatternSettingModel": IgnorePatternSettingModel,
    "ImportedLinksSetting": ImportedLinksSetting,
    "IncrementalApiModel": IncrementalApiModel,
    "IntegrationUserMappingItemModel": IntegrationUserMappingItemModel,
    "IntegrationWizardResultModel": IntegrationWizardResultModel,
    "IssueApiModel": IssueApiModel,
    "IssueApiModelCvssVector": IssueApiModelCvssVector,
    "IssueApiResult": IssueApiResult,
    "IssueApiUpdateModel": IssueApiUpdateModel,
    "IssueHistoryApiModel": IssueHistoryApiModel,
    "IssueReportFilterApiModel": IssueReportFilterApiModel,
    "IssueRequestContentParametersApiModel": IssueRequestContentParametersApiModel,
    "JavaScriptSettingsModel": JavaScriptSettingsModel,
    "JiraIntegrationInfoModel": JiraIntegrationInfoModel,
    "KafkaIntegrationInfoModel": KafkaIntegrationInfoModel,
    "KennaIntegrationInfoModel": KennaIntegrationInfoModel,
    "LicenseBaseModel": LicenseBaseModel,
    "LogoutKeywordPatternModel": LogoutKeywordPatternModel,
    "MattermostIntegrationInfoModel": MattermostIntegrationInfoModel,
    "MemberApiModelListApiResult": MemberApiModelListApiResult,
    "MemberApiViewModel": MemberApiViewModel,
    "MemberInvitationApiModelListApiResult": MemberInvitationApiModelListApiResult,
    "MemberInvitationApiViewModel": MemberInvitationApiViewModel,
    "MicrosoftTeamsIntegrationInfoModel": MicrosoftTeamsIntegrationInfoModel,
    "NameValuePair": NameValuePair,
    "NewGroupScanApiModel": NewGroupScanApiModel,
    "NewMemberApiModel": NewMemberApiModel,
    "NewMemberInvitationApiModel": NewMemberInvitationApiModel,
    "NewRoleApiModel": NewRoleApiModel,
    "NewScanNotificationApiModel": NewScanNotificationApiModel,
    "NewScanNotificationRecipientApiModel": NewScanNotificationRecipientApiModel,
    "NewScanPolicySettingModel": NewScanPolicySettingModel,
    "NewScanTaskApiModel": NewScanTaskApiModel,
    "NewScanTaskWithProfileApiModel": NewScanTaskWithProfileApiModel,
    "NewScheduledIncrementalScanApiModel": NewScheduledIncrementalScanApiModel,
    "NewScheduledScanApiModel": NewScheduledScanApiModel,
    "NewScheduledWithProfileApiModel": NewScheduledWithProfileApiModel,
    "NewTeamApiModel": NewTeamApiModel,
    "NewWebsiteApiModel": NewWebsiteApiModel,
    "NewWebsiteGroupApiModel": NewWebsiteGroupApiModel,
    "NotificationIntegrationCustomFieldModel": NotificationIntegrationCustomFieldModel,
    "NotificationPriorityPair": NotificationPriorityPair,
    "OAuth2SettingApiModel": OAuth2SettingApiModel,
    "OAuth2SettingEndPointModel": OAuth2SettingEndPointModel,
    "OAuth2SettingEndpoint": OAuth2SettingEndpoint,
    "OAuth2SettingModel": OAuth2SettingModel,
    "OtpSettings": OtpSettings,
    "OutsiderRecipient": OutsiderRecipient,
    "PagerDutyIntegrationInfoModel": PagerDutyIntegrationInfoModel,
    "PciScanTaskViewModel": PciScanTaskViewModel,
    "PermissionApiModel": PermissionApiModel,
    "PivotalTrackerIntegrationInfoModel": PivotalTrackerIntegrationInfoModel,
    "PreRequestScriptSettingModel": PreRequestScriptSettingModel,
    "ProxySettingsModel": ProxySettingsModel,
    "RedmineIntegrationInfoModel": RedmineIntegrationInfoModel,
    "ReducedMemberApiViewModel": ReducedMemberApiViewModel,
    "ReducedScanTaskProfile": ReducedScanTaskProfile,
    "ReducedTeamApiViewModel": ReducedTeamApiViewModel,
    "ResponseFields": ResponseFields,
    "RoleApiModelListApiResult": RoleApiModelListApiResult,
    "RoleApiViewModel": RoleApiViewModel,
    "RoleWebsiteGroupMappingApiModel": RoleWebsiteGroupMappingApiModel,
    "RoleWebsiteGroupMappingApiViewModel": RoleWebsiteGroupMappingApiViewModel,
    "SaveScanProfileApiModel": SaveScanProfileApiModel,
    "ScanCustomReportApiModel": ScanCustomReportApiModel,
    "ScanNotificationApiModel": ScanNotificationApiModel,
    "ScanNotificationIntegrationViewModel": ScanNotificationIntegrationViewModel,
    "ScanNotificationListApiResult": ScanNotificationListApiResult,
    "ScanNotificationRecipientApiModel": ScanNotificationRecipientApiModel,
    "ScanNotificationRecipientUserApiModel": ScanNotificationRecipientUserApiModel,
    "ScanNotificationScanTaskGroupApiModel": ScanNotificationScanTaskGroupApiModel,
    "ScanPolicyListApiResult": ScanPolicyListApiResult,
    "ScanPolicyOptimizerOptions": ScanPolicyOptimizerOptions,
    "ScanPolicyPatternModel": ScanPolicyPatternModel,
    "ScanPolicySettingApiModel": ScanPolicySettingApiModel,
    "ScanPolicySettingItemApiModel": ScanPolicySettingItemApiModel,
    "ScanReportApiModel": ScanReportApiModel,
    "ScanTaskListApiResult": ScanTaskListApiResult,
    "ScanTaskModel": ScanTaskModel,
    "ScanTimeWindowItemModel": ScanTimeWindowItemModel,
    "ScanTimeWindowItemViewModel": ScanTimeWindowItemViewModel,
    "ScanTimeWindowModel": ScanTimeWindowModel,
    "ScanTimeWindowViewModel": ScanTimeWindowViewModel,
    "ScheduledScanListApiResult": ScheduledScanListApiResult,
    "ScheduledScanModel": ScheduledScanModel,
    "ScheduledScanRecurrenceApiModel": ScheduledScanRecurrenceApiModel,
    "ScheduledScanRecurrenceViewModel": ScheduledScanRecurrenceViewModel,
    "ScopeSetting": ScopeSetting,
    "ScopeSettingModel": ScopeSettingModel,
    "SecurityCheckGroupModel": SecurityCheckGroupModel,
    "SecurityCheckGroupParentModel": SecurityCheckGroupParentModel,
    "SecurityCheckSetting": SecurityCheckSetting,
    "SelectOptionModel": SelectOptionModel,
    "SendVerificationEmailModel": SendVerificationEmailModel,
    "SensitiveKeywordSettingModel": SensitiveKeywordSettingModel,
    "ServiceNowIntegrationInfoModel": ServiceNowIntegrationInfoModel,
    "SharkModel": SharkModel,
    "SlackIntegrationInfoModel": SlackIntegrationInfoModel,
    "SslTlsSettingModel": SslTlsSettingModel,
    "StartVerificationApiModel": StartVerificationApiModel,
    "StartVerificationResult": StartVerificationResult,
    "TFSIntegrationInfoModel": TFSIntegrationInfoModel,
    "TeamApiModelListApiResult": TeamApiModelListApiResult,
    "TeamApiViewModel": TeamApiViewModel,
    "TechnologyApiModel": TechnologyApiModel,
    "TechnologyListApiResult": TechnologyListApiResult,
    "TestScanProfileCredentialsRequestModel": TestScanProfileCredentialsRequestModel,
    "ThreeLeggedFields": ThreeLeggedFields,
    "TimezoneApiModel": TimezoneApiModel,
    "TrelloBoard": TrelloBoard,
    "TrelloIntegrationInfoModel": TrelloIntegrationInfoModel,
    "TrelloLabel": TrelloLabel,
    "TrelloList": TrelloList,
    "TrelloMember": TrelloMember,
    "UnfuddleIntegrationInfoModel": UnfuddleIntegrationInfoModel,
    "UpdateMemberApiModel": UpdateMemberApiModel,
    "UpdateRoleApiModel": UpdateRoleApiModel,
    "UpdateScanNotificationApiModel": UpdateScanNotificationApiModel,
    "UpdateScanPolicySettingModel": UpdateScanPolicySettingModel,
    "UpdateScheduledIncrementalScanApiModel": UpdateScheduledIncrementalScanApiModel,
    "UpdateScheduledScanApiModel": UpdateScheduledScanApiModel,
    "UpdateScheduledScanModel": UpdateScheduledScanModel,
    "UpdateTeamApiModel": UpdateTeamApiModel,
    "UpdateWebsiteApiModel": UpdateWebsiteApiModel,
    "UpdateWebsiteGroupApiModel": UpdateWebsiteGroupApiModel,
    "UrlRewriteExcludedPathModel": UrlRewriteExcludedPathModel,
    "UrlRewriteRuleModel": UrlRewriteRuleModel,
    "UrlRewriteSetting": UrlRewriteSetting,
    "UserApiTokenModel": UserApiTokenModel,
    "UserHealthCheckApiModel": UserHealthCheckApiModel,
    "VcsCommitInfo": VcsCommitInfo,
    "VerifyApiModel": VerifyApiModel,
    "VersionIssue": VersionIssue,
    "VulnerabilityClassification": VulnerabilityClassification,
    "VulnerabilityContentApiModel": VulnerabilityContentApiModel,
    "VulnerabilityModel": VulnerabilityModel,
    "VulnerabilityTemplate": VulnerabilityTemplate,
    "VulnerabilityTemplateCvss31Vector": VulnerabilityTemplateCvss31Vector,
    "VulnerabilityTemplateCvssVector": VulnerabilityTemplateCvssVector,
    "WebStorageSetting": WebStorageSetting,
    "WebhookIntegrationInfoModel": WebhookIntegrationInfoModel,
    "WebsiteApiModel": WebsiteApiModel,
    "WebsiteGroupApiModel": WebsiteGroupApiModel,
    "WebsiteGroupListApiResult": WebsiteGroupListApiResult,
    "WebsiteGroupModel": WebsiteGroupModel,
    "WebsiteListApiResult": WebsiteListApiResult,
    "YouTrackIntegrationInfoModel": YouTrackIntegrationInfoModel,
    "ZapierIntegrationInfoModel": ZapierIntegrationInfoModel,
}

export class ObjectSerializer {
    public static findCorrectType(data: any, expectedType: string) {
        if (data == undefined) {
            return expectedType;
        } else if (primitives.indexOf(expectedType.toLowerCase()) !== -1) {
            return expectedType;
        } else if (expectedType === "Date") {
            return expectedType;
        } else {
            if (enumsMap[expectedType]) {
                return expectedType;
            }

            if (!typeMap[expectedType]) {
                return expectedType; // w/e we don't know the type
            }

            // Check the discriminator
            let discriminatorProperty = typeMap[expectedType].discriminator;
            if (discriminatorProperty == null) {
                return expectedType; // the type does not have a discriminator. use it.
            } else {
                if (data[discriminatorProperty]) {
                    var discriminatorType = data[discriminatorProperty];
                    if(typeMap[discriminatorType]){
                        return discriminatorType; // use the type given in the discriminator
                    } else {
                        return expectedType; // discriminator did not map to a type
                    }
                } else {
                    return expectedType; // discriminator was not present (or an empty string)
                }
            }
        }
    }

    public static serialize(data: any, type: string) {
        if (data == undefined) {
            return data;
        } else if (primitives.indexOf(type.toLowerCase()) !== -1) {
            return data;
        } else if (type.lastIndexOf("Array<", 0) === 0) { // string.startsWith pre es6
            let subType: string = type.replace("Array<", ""); // Array<Type> => Type>
            subType = subType.substring(0, subType.length - 1); // Type> => Type
            let transformedData: any[] = [];
            for (let index = 0; index < data.length; index++) {
                let datum = data[index];
                transformedData.push(ObjectSerializer.serialize(datum, subType));
            }
            return transformedData;
        } else if (type === "Date") {
            return data.toISOString();
        } else {
            if (enumsMap[type]) {
                return data;
            }
            if (!typeMap[type]) { // in case we dont know the type
                return data;
            }

            // Get the actual type of this object
            type = this.findCorrectType(data, type);

            // get the map for the correct type.
            let attributeTypes = typeMap[type].getAttributeTypeMap();
            let instance: {[index: string]: any} = {};
            for (let index = 0; index < attributeTypes.length; index++) {
                let attributeType = attributeTypes[index];
                instance[attributeType.baseName] = ObjectSerializer.serialize(data[attributeType.name], attributeType.type);
            }
            return instance;
        }
    }

    public static deserialize(data: any, type: string) {
        // polymorphism may change the actual type.
        type = ObjectSerializer.findCorrectType(data, type);
        if (data == undefined) {
            return data;
        } else if (primitives.indexOf(type.toLowerCase()) !== -1) {
            return data;
        } else if (type.lastIndexOf("Array<", 0) === 0) { // string.startsWith pre es6
            let subType: string = type.replace("Array<", ""); // Array<Type> => Type>
            subType = subType.substring(0, subType.length - 1); // Type> => Type
            let transformedData: any[] = [];
            for (let index = 0; index < data.length; index++) {
                let datum = data[index];
                transformedData.push(ObjectSerializer.deserialize(datum, subType));
            }
            return transformedData;
        } else if (type === "Date") {
            return new Date(data);
        } else {
            if (enumsMap[type]) {// is Enum
                return data;
            }

            if (!typeMap[type]) { // dont know the type
                return data;
            }
            let instance = new typeMap[type]();
            let attributeTypes = typeMap[type].getAttributeTypeMap();
            for (let index = 0; index < attributeTypes.length; index++) {
                let attributeType = attributeTypes[index];
                instance[attributeType.name] = ObjectSerializer.deserialize(data[attributeType.baseName], attributeType.type);
            }
            return instance;
        }
    }
}

export interface Authentication {
    /**
    * Apply authentication settings to header and query params.
    */
    applyToRequest(requestOptions: localVarRequest.Options): Promise<void> | void;
}

export class HttpBasicAuth implements Authentication {
    public username: string = '';
    public password: string = '';

    applyToRequest(requestOptions: localVarRequest.Options): void {
        requestOptions.auth = {
            username: this.username, password: this.password
        }
    }
}

export class HttpBearerAuth implements Authentication {
    public accessToken: string | (() => string) = '';

    applyToRequest(requestOptions: localVarRequest.Options): void {
        if (requestOptions && requestOptions.headers) {
            const accessToken = typeof this.accessToken === 'function'
                            ? this.accessToken()
                            : this.accessToken;
            requestOptions.headers["Authorization"] = "Bearer " + accessToken;
        }
    }
}

export class ApiKeyAuth implements Authentication {
    public apiKey: string = '';

    constructor(private location: string, private paramName: string) {
    }

    applyToRequest(requestOptions: localVarRequest.Options): void {
        if (this.location == "query") {
            (<any>requestOptions.qs)[this.paramName] = this.apiKey;
        } else if (this.location == "header" && requestOptions && requestOptions.headers) {
            requestOptions.headers[this.paramName] = this.apiKey;
        } else if (this.location == 'cookie' && requestOptions && requestOptions.headers) {
            if (requestOptions.headers['Cookie']) {
                requestOptions.headers['Cookie'] += '; ' + this.paramName + '=' + encodeURIComponent(this.apiKey);
            }
            else {
                requestOptions.headers['Cookie'] = this.paramName + '=' + encodeURIComponent(this.apiKey);
            }
        }
    }
}

export class OAuth implements Authentication {
    public accessToken: string = '';

    applyToRequest(requestOptions: localVarRequest.Options): void {
        if (requestOptions && requestOptions.headers) {
            requestOptions.headers["Authorization"] = "Bearer " + this.accessToken;
        }
    }
}

export class VoidAuth implements Authentication {
    public username: string = '';
    public password: string = '';

    applyToRequest(_: localVarRequest.Options): void {
        // Do nothing
    }
}

export type Interceptor = (requestOptions: localVarRequest.Options) => (Promise<void> | void);
