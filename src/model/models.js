"use strict";
function __export(m) {
    for (var p in m) if (!exports.hasOwnProperty(p)) exports[p] = m[p];
}
Object.defineProperty(exports, "__esModule", { value: true });
__export(require("./accessTokenTableModel"));
__export(require("./accountLicenseApiModel"));
__export(require("./additionalWebsiteModel"));
__export(require("./additionalWebsitesSettingModel"));
__export(require("./agentGroupApiDeleteModel"));
__export(require("./agentGroupApiModel"));
__export(require("./agentGroupApiNewModel"));
__export(require("./agentGroupApiUpdateModel"));
__export(require("./agentGroupModel"));
__export(require("./agentGroupsListApiResult"));
__export(require("./agentListApiModel"));
__export(require("./agentListApiResult"));
__export(require("./agentSelectionModel"));
__export(require("./agentStatusModel"));
__export(require("./apiFileModel"));
__export(require("./apiScanStatusModel"));
__export(require("./asanaIntegrationInfoModel"));
__export(require("./asanaProject"));
__export(require("./asanaTag"));
__export(require("./asanaUser"));
__export(require("./asanaWorkspace"));
__export(require("./attackingSettingModel"));
__export(require("./authVerificationApiResult"));
__export(require("./authenticationProfileViewModel"));
__export(require("./authorizationCodeTableModel"));
__export(require("./autoCompleteSettingModel"));
__export(require("./azureDevOpsIntegrationInfoModel"));
__export(require("./baseScanApiModel"));
__export(require("./basicAuthenticationCredentialApiModel"));
__export(require("./basicAuthenticationCredentialModel"));
__export(require("./basicAuthenticationSettingApiModel"));
__export(require("./basicAuthenticationSettingModel"));
__export(require("./bitbucketIntegrationInfoModel"));
__export(require("./bruteForceSettingModel"));
__export(require("./bugzillaIntegrationInfoModel"));
__export(require("./clientCertificateAuthenticationApiModel"));
__export(require("./clientCertificateAuthenticationViewModel"));
__export(require("./clubhouseIntegrationInfoModel"));
__export(require("./contentTypeModel"));
__export(require("./contentTypeTemplate"));
__export(require("./crawlingSettingModel"));
__export(require("./csrfSettingModel"));
__export(require("./custom404SettingModel"));
__export(require("./customFieldModel"));
__export(require("./customHttpHeaderModel"));
__export(require("./customHttpHeaderSetting"));
__export(require("./customScriptPageViewModel"));
__export(require("./customTemplateContentModel"));
__export(require("./customTemplateModel"));
__export(require("./cvssMetricModel"));
__export(require("./cvssScoreValue"));
__export(require("./cyberArkVaultIntegrationInfoModel"));
__export(require("./deleteAgentModel"));
__export(require("./deleteScanNotificationApiModel"));
__export(require("./deleteWebsiteApiModel"));
__export(require("./deleteWebsiteGroupApiModel"));
__export(require("./discoveryApiModel"));
__export(require("./discoveryServiceListApiResult"));
__export(require("./discoverySettingsApiModel"));
__export(require("./emailPatternSetting"));
__export(require("./excludeFilter"));
__export(require("./excludedLinkModel"));
__export(require("./excludedUsageTrackerModel"));
__export(require("./extensionSettingModel"));
__export(require("./fileCache"));
__export(require("./fogBugzIntegrationInfoModel"));
__export(require("./formAuthenticationCustomScript"));
__export(require("./formAuthenticationCyberArkVaultSetting"));
__export(require("./formAuthenticationHashicorpVaultSetting"));
__export(require("./formAuthenticationPersona"));
__export(require("./formAuthenticationSettingApiModel"));
__export(require("./formAuthenticationSettingModel"));
__export(require("./formAuthenticationVerificationApiModel"));
__export(require("./formValueSettingModel"));
__export(require("./freshserviceEntity"));
__export(require("./freshserviceIntegrationInfoModel"));
__export(require("./freshserviceUser"));
__export(require("./gitHubIntegrationInfoModel"));
__export(require("./gitLabIntegrationInfoModel"));
__export(require("./hashicorpVaultIntegrationInfoModel"));
__export(require("./headerAuthenticationModel"));
__export(require("./httpRequestSettingModel"));
__export(require("./idNamePair"));
__export(require("./ignorePatternSettingModel"));
__export(require("./importedLinksSetting"));
__export(require("./incrementalApiModel"));
__export(require("./integrationUserMappingItemModel"));
__export(require("./integrationWizardResultModel"));
__export(require("./issueApiModel"));
__export(require("./issueApiModelCvssVector"));
__export(require("./issueApiResult"));
__export(require("./issueApiUpdateModel"));
__export(require("./issueHistoryApiModel"));
__export(require("./issueReportFilterApiModel"));
__export(require("./issueRequestContentParametersApiModel"));
__export(require("./javaScriptSettingsModel"));
__export(require("./jiraIntegrationInfoModel"));
__export(require("./kafkaIntegrationInfoModel"));
__export(require("./kennaIntegrationInfoModel"));
__export(require("./licenseBaseModel"));
__export(require("./logoutKeywordPatternModel"));
__export(require("./mattermostIntegrationInfoModel"));
__export(require("./microsoftTeamsIntegrationInfoModel"));
__export(require("./nameValuePair"));
__export(require("./newGroupScanApiModel"));
__export(require("./newScanNotificationApiModel"));
__export(require("./newScanNotificationRecipientApiModel"));
__export(require("./newScanPolicySettingModel"));
__export(require("./newScanTaskApiModel"));
__export(require("./newScanTaskWithProfileApiModel"));
__export(require("./newScheduledIncrementalScanApiModel"));
__export(require("./newScheduledScanApiModel"));
__export(require("./newScheduledWithProfileApiModel"));
__export(require("./newUserApiModel"));
__export(require("./newWebsiteApiModel"));
__export(require("./newWebsiteGroupApiModel"));
__export(require("./notificationIntegrationCustomFieldModel"));
__export(require("./notificationPriorityPair"));
__export(require("./oAuth2SettingApiModel"));
__export(require("./oAuth2SettingEndPointModel"));
__export(require("./oAuth2SettingEndpoint"));
__export(require("./oAuth2SettingModel"));
__export(require("./otpSettings"));
__export(require("./outsiderRecipient"));
__export(require("./pagerDutyIntegrationInfoModel"));
__export(require("./pciScanTaskViewModel"));
__export(require("./pivotalTrackerIntegrationInfoModel"));
__export(require("./preRequestScriptSettingModel"));
__export(require("./proxySettingsModel"));
__export(require("./redmineIntegrationInfoModel"));
__export(require("./reducedScanTaskProfile"));
__export(require("./responseFields"));
__export(require("./saveScanProfileApiModel"));
__export(require("./scanCustomReportApiModel"));
__export(require("./scanNotificationApiModel"));
__export(require("./scanNotificationIntegrationViewModel"));
__export(require("./scanNotificationListApiResult"));
__export(require("./scanNotificationRecipientApiModel"));
__export(require("./scanNotificationRecipientUserApiModel"));
__export(require("./scanNotificationScanTaskGroupApiModel"));
__export(require("./scanPolicyListApiResult"));
__export(require("./scanPolicyOptimizerOptions"));
__export(require("./scanPolicyPatternModel"));
__export(require("./scanPolicySettingApiModel"));
__export(require("./scanPolicySettingItemApiModel"));
__export(require("./scanProfilesListApiResult"));
__export(require("./scanReportApiModel"));
__export(require("./scanTaskListApiResult"));
__export(require("./scanTaskModel"));
__export(require("./scanTimeWindowItemModel"));
__export(require("./scanTimeWindowItemViewModel"));
__export(require("./scanTimeWindowModel"));
__export(require("./scanTimeWindowViewModel"));
__export(require("./scheduledScanListApiResult"));
__export(require("./scheduledScanModel"));
__export(require("./scheduledScanRecurrenceApiModel"));
__export(require("./scheduledScanRecurrenceViewModel"));
__export(require("./scopeSetting"));
__export(require("./scopeSettingModel"));
__export(require("./securityCheckGroupModel"));
__export(require("./securityCheckGroupParentModel"));
__export(require("./securityCheckSetting"));
__export(require("./selectOptionModel"));
__export(require("./sendVerificationEmailModel"));
__export(require("./sensitiveKeywordSettingModel"));
__export(require("./serviceNowIntegrationInfoModel"));
__export(require("./sharkModel"));
__export(require("./slackIntegrationInfoModel"));
__export(require("./sslTlsSettingModel"));
__export(require("./startVerificationApiModel"));
__export(require("./startVerificationResult"));
__export(require("./tFSIntegrationInfoModel"));
__export(require("./technologyApiModel"));
__export(require("./technologyListApiResult"));
__export(require("./testScanProfileCredentialsRequestModel"));
__export(require("./threeLeggedFields"));
__export(require("./timezoneApiModel"));
__export(require("./trelloBoard"));
__export(require("./trelloIntegrationInfoModel"));
__export(require("./trelloLabel"));
__export(require("./trelloList"));
__export(require("./trelloMember"));
__export(require("./unfuddleIntegrationInfoModel"));
__export(require("./updateScanNotificationApiModel"));
__export(require("./updateScanPolicySettingModel"));
__export(require("./updateScheduledIncrementalScanApiModel"));
__export(require("./updateScheduledScanApiModel"));
__export(require("./updateScheduledScanModel"));
__export(require("./updateUserApiModel"));
__export(require("./updateWebsiteApiModel"));
__export(require("./updateWebsiteGroupApiModel"));
__export(require("./urlRewriteExcludedPathModel"));
__export(require("./urlRewriteRuleModel"));
__export(require("./urlRewriteSetting"));
__export(require("./userApiModel"));
__export(require("./userApiTokenModel"));
__export(require("./userHealthCheckApiModel"));
__export(require("./userListApiResult"));
__export(require("./vcsCommitInfo"));
__export(require("./verifyApiModel"));
__export(require("./versionIssue"));
__export(require("./vulnerabilityClassification"));
__export(require("./vulnerabilityContentApiModel"));
__export(require("./vulnerabilityModel"));
__export(require("./vulnerabilityTemplate"));
__export(require("./vulnerabilityTemplateCvss31Vector"));
__export(require("./vulnerabilityTemplateCvssVector"));
__export(require("./webStorageSetting"));
__export(require("./webhookIntegrationInfoModel"));
__export(require("./websiteApiModel"));
__export(require("./websiteGroupApiModel"));
__export(require("./websiteGroupListApiResult"));
__export(require("./websiteGroupModel"));
__export(require("./websiteListApiResult"));
__export(require("./youTrackIntegrationInfoModel"));
__export(require("./zapierIntegrationInfoModel"));
const accessTokenTableModel_1 = require("./accessTokenTableModel");
const accountLicenseApiModel_1 = require("./accountLicenseApiModel");
const additionalWebsiteModel_1 = require("./additionalWebsiteModel");
const additionalWebsitesSettingModel_1 = require("./additionalWebsitesSettingModel");
const agentGroupApiDeleteModel_1 = require("./agentGroupApiDeleteModel");
const agentGroupApiModel_1 = require("./agentGroupApiModel");
const agentGroupApiNewModel_1 = require("./agentGroupApiNewModel");
const agentGroupApiUpdateModel_1 = require("./agentGroupApiUpdateModel");
const agentGroupModel_1 = require("./agentGroupModel");
const agentGroupsListApiResult_1 = require("./agentGroupsListApiResult");
const agentListApiModel_1 = require("./agentListApiModel");
const agentListApiResult_1 = require("./agentListApiResult");
const agentSelectionModel_1 = require("./agentSelectionModel");
const agentStatusModel_1 = require("./agentStatusModel");
const apiFileModel_1 = require("./apiFileModel");
const apiScanStatusModel_1 = require("./apiScanStatusModel");
const asanaIntegrationInfoModel_1 = require("./asanaIntegrationInfoModel");
const asanaProject_1 = require("./asanaProject");
const asanaTag_1 = require("./asanaTag");
const asanaUser_1 = require("./asanaUser");
const asanaWorkspace_1 = require("./asanaWorkspace");
const attackingSettingModel_1 = require("./attackingSettingModel");
const authVerificationApiResult_1 = require("./authVerificationApiResult");
const authenticationProfileViewModel_1 = require("./authenticationProfileViewModel");
const authorizationCodeTableModel_1 = require("./authorizationCodeTableModel");
const autoCompleteSettingModel_1 = require("./autoCompleteSettingModel");
const azureDevOpsIntegrationInfoModel_1 = require("./azureDevOpsIntegrationInfoModel");
const baseScanApiModel_1 = require("./baseScanApiModel");
const basicAuthenticationCredentialApiModel_1 = require("./basicAuthenticationCredentialApiModel");
const basicAuthenticationCredentialModel_1 = require("./basicAuthenticationCredentialModel");
const basicAuthenticationSettingApiModel_1 = require("./basicAuthenticationSettingApiModel");
const basicAuthenticationSettingModel_1 = require("./basicAuthenticationSettingModel");
const bitbucketIntegrationInfoModel_1 = require("./bitbucketIntegrationInfoModel");
const bruteForceSettingModel_1 = require("./bruteForceSettingModel");
const bugzillaIntegrationInfoModel_1 = require("./bugzillaIntegrationInfoModel");
const clientCertificateAuthenticationApiModel_1 = require("./clientCertificateAuthenticationApiModel");
const clientCertificateAuthenticationViewModel_1 = require("./clientCertificateAuthenticationViewModel");
const clubhouseIntegrationInfoModel_1 = require("./clubhouseIntegrationInfoModel");
const contentTypeModel_1 = require("./contentTypeModel");
const contentTypeTemplate_1 = require("./contentTypeTemplate");
const crawlingSettingModel_1 = require("./crawlingSettingModel");
const csrfSettingModel_1 = require("./csrfSettingModel");
const custom404SettingModel_1 = require("./custom404SettingModel");
const customFieldModel_1 = require("./customFieldModel");
const customHttpHeaderModel_1 = require("./customHttpHeaderModel");
const customHttpHeaderSetting_1 = require("./customHttpHeaderSetting");
const customScriptPageViewModel_1 = require("./customScriptPageViewModel");
const customTemplateContentModel_1 = require("./customTemplateContentModel");
const customTemplateModel_1 = require("./customTemplateModel");
const cvssMetricModel_1 = require("./cvssMetricModel");
const cvssScoreValue_1 = require("./cvssScoreValue");
const cyberArkVaultIntegrationInfoModel_1 = require("./cyberArkVaultIntegrationInfoModel");
const deleteAgentModel_1 = require("./deleteAgentModel");
const deleteScanNotificationApiModel_1 = require("./deleteScanNotificationApiModel");
const deleteWebsiteApiModel_1 = require("./deleteWebsiteApiModel");
const deleteWebsiteGroupApiModel_1 = require("./deleteWebsiteGroupApiModel");
const discoveryApiModel_1 = require("./discoveryApiModel");
const discoveryServiceListApiResult_1 = require("./discoveryServiceListApiResult");
const discoverySettingsApiModel_1 = require("./discoverySettingsApiModel");
const emailPatternSetting_1 = require("./emailPatternSetting");
const excludeFilter_1 = require("./excludeFilter");
const excludedLinkModel_1 = require("./excludedLinkModel");
const excludedUsageTrackerModel_1 = require("./excludedUsageTrackerModel");
const extensionSettingModel_1 = require("./extensionSettingModel");
const fileCache_1 = require("./fileCache");
const fogBugzIntegrationInfoModel_1 = require("./fogBugzIntegrationInfoModel");
const formAuthenticationCustomScript_1 = require("./formAuthenticationCustomScript");
const formAuthenticationCyberArkVaultSetting_1 = require("./formAuthenticationCyberArkVaultSetting");
const formAuthenticationHashicorpVaultSetting_1 = require("./formAuthenticationHashicorpVaultSetting");
const formAuthenticationPersona_1 = require("./formAuthenticationPersona");
const formAuthenticationSettingApiModel_1 = require("./formAuthenticationSettingApiModel");
const formAuthenticationSettingModel_1 = require("./formAuthenticationSettingModel");
const formAuthenticationVerificationApiModel_1 = require("./formAuthenticationVerificationApiModel");
const formValueSettingModel_1 = require("./formValueSettingModel");
const freshserviceEntity_1 = require("./freshserviceEntity");
const freshserviceIntegrationInfoModel_1 = require("./freshserviceIntegrationInfoModel");
const freshserviceUser_1 = require("./freshserviceUser");
const gitHubIntegrationInfoModel_1 = require("./gitHubIntegrationInfoModel");
const gitLabIntegrationInfoModel_1 = require("./gitLabIntegrationInfoModel");
const hashicorpVaultIntegrationInfoModel_1 = require("./hashicorpVaultIntegrationInfoModel");
const headerAuthenticationModel_1 = require("./headerAuthenticationModel");
const httpRequestSettingModel_1 = require("./httpRequestSettingModel");
const idNamePair_1 = require("./idNamePair");
const ignorePatternSettingModel_1 = require("./ignorePatternSettingModel");
const importedLinksSetting_1 = require("./importedLinksSetting");
const incrementalApiModel_1 = require("./incrementalApiModel");
const integrationUserMappingItemModel_1 = require("./integrationUserMappingItemModel");
const integrationWizardResultModel_1 = require("./integrationWizardResultModel");
const issueApiModel_1 = require("./issueApiModel");
const issueApiModelCvssVector_1 = require("./issueApiModelCvssVector");
const issueApiResult_1 = require("./issueApiResult");
const issueApiUpdateModel_1 = require("./issueApiUpdateModel");
const issueHistoryApiModel_1 = require("./issueHistoryApiModel");
const issueReportFilterApiModel_1 = require("./issueReportFilterApiModel");
const issueRequestContentParametersApiModel_1 = require("./issueRequestContentParametersApiModel");
const javaScriptSettingsModel_1 = require("./javaScriptSettingsModel");
const jiraIntegrationInfoModel_1 = require("./jiraIntegrationInfoModel");
const kafkaIntegrationInfoModel_1 = require("./kafkaIntegrationInfoModel");
const kennaIntegrationInfoModel_1 = require("./kennaIntegrationInfoModel");
const licenseBaseModel_1 = require("./licenseBaseModel");
const logoutKeywordPatternModel_1 = require("./logoutKeywordPatternModel");
const mattermostIntegrationInfoModel_1 = require("./mattermostIntegrationInfoModel");
const microsoftTeamsIntegrationInfoModel_1 = require("./microsoftTeamsIntegrationInfoModel");
const nameValuePair_1 = require("./nameValuePair");
const newGroupScanApiModel_1 = require("./newGroupScanApiModel");
const newScanNotificationApiModel_1 = require("./newScanNotificationApiModel");
const newScanNotificationRecipientApiModel_1 = require("./newScanNotificationRecipientApiModel");
const newScanPolicySettingModel_1 = require("./newScanPolicySettingModel");
const newScanTaskApiModel_1 = require("./newScanTaskApiModel");
const newScanTaskWithProfileApiModel_1 = require("./newScanTaskWithProfileApiModel");
const newScheduledIncrementalScanApiModel_1 = require("./newScheduledIncrementalScanApiModel");
const newScheduledScanApiModel_1 = require("./newScheduledScanApiModel");
const newScheduledWithProfileApiModel_1 = require("./newScheduledWithProfileApiModel");
const newUserApiModel_1 = require("./newUserApiModel");
const newWebsiteApiModel_1 = require("./newWebsiteApiModel");
const newWebsiteGroupApiModel_1 = require("./newWebsiteGroupApiModel");
const notificationIntegrationCustomFieldModel_1 = require("./notificationIntegrationCustomFieldModel");
const notificationPriorityPair_1 = require("./notificationPriorityPair");
const oAuth2SettingApiModel_1 = require("./oAuth2SettingApiModel");
const oAuth2SettingEndPointModel_1 = require("./oAuth2SettingEndPointModel");
const oAuth2SettingEndpoint_1 = require("./oAuth2SettingEndpoint");
const oAuth2SettingModel_1 = require("./oAuth2SettingModel");
const otpSettings_1 = require("./otpSettings");
const outsiderRecipient_1 = require("./outsiderRecipient");
const pagerDutyIntegrationInfoModel_1 = require("./pagerDutyIntegrationInfoModel");
const pciScanTaskViewModel_1 = require("./pciScanTaskViewModel");
const pivotalTrackerIntegrationInfoModel_1 = require("./pivotalTrackerIntegrationInfoModel");
const preRequestScriptSettingModel_1 = require("./preRequestScriptSettingModel");
const proxySettingsModel_1 = require("./proxySettingsModel");
const redmineIntegrationInfoModel_1 = require("./redmineIntegrationInfoModel");
const reducedScanTaskProfile_1 = require("./reducedScanTaskProfile");
const responseFields_1 = require("./responseFields");
const saveScanProfileApiModel_1 = require("./saveScanProfileApiModel");
const scanCustomReportApiModel_1 = require("./scanCustomReportApiModel");
const scanNotificationApiModel_1 = require("./scanNotificationApiModel");
const scanNotificationIntegrationViewModel_1 = require("./scanNotificationIntegrationViewModel");
const scanNotificationListApiResult_1 = require("./scanNotificationListApiResult");
const scanNotificationRecipientApiModel_1 = require("./scanNotificationRecipientApiModel");
const scanNotificationRecipientUserApiModel_1 = require("./scanNotificationRecipientUserApiModel");
const scanNotificationScanTaskGroupApiModel_1 = require("./scanNotificationScanTaskGroupApiModel");
const scanPolicyListApiResult_1 = require("./scanPolicyListApiResult");
const scanPolicyOptimizerOptions_1 = require("./scanPolicyOptimizerOptions");
const scanPolicyPatternModel_1 = require("./scanPolicyPatternModel");
const scanPolicySettingApiModel_1 = require("./scanPolicySettingApiModel");
const scanPolicySettingItemApiModel_1 = require("./scanPolicySettingItemApiModel");
const scanProfilesListApiResult_1 = require("./scanProfilesListApiResult");
const scanReportApiModel_1 = require("./scanReportApiModel");
const scanTaskListApiResult_1 = require("./scanTaskListApiResult");
const scanTaskModel_1 = require("./scanTaskModel");
const scanTimeWindowItemModel_1 = require("./scanTimeWindowItemModel");
const scanTimeWindowItemViewModel_1 = require("./scanTimeWindowItemViewModel");
const scanTimeWindowModel_1 = require("./scanTimeWindowModel");
const scanTimeWindowViewModel_1 = require("./scanTimeWindowViewModel");
const scheduledScanListApiResult_1 = require("./scheduledScanListApiResult");
const scheduledScanModel_1 = require("./scheduledScanModel");
const scheduledScanRecurrenceApiModel_1 = require("./scheduledScanRecurrenceApiModel");
const scheduledScanRecurrenceViewModel_1 = require("./scheduledScanRecurrenceViewModel");
const scopeSetting_1 = require("./scopeSetting");
const scopeSettingModel_1 = require("./scopeSettingModel");
const securityCheckGroupModel_1 = require("./securityCheckGroupModel");
const securityCheckGroupParentModel_1 = require("./securityCheckGroupParentModel");
const securityCheckSetting_1 = require("./securityCheckSetting");
const selectOptionModel_1 = require("./selectOptionModel");
const sendVerificationEmailModel_1 = require("./sendVerificationEmailModel");
const sensitiveKeywordSettingModel_1 = require("./sensitiveKeywordSettingModel");
const serviceNowIntegrationInfoModel_1 = require("./serviceNowIntegrationInfoModel");
const sharkModel_1 = require("./sharkModel");
const slackIntegrationInfoModel_1 = require("./slackIntegrationInfoModel");
const sslTlsSettingModel_1 = require("./sslTlsSettingModel");
const startVerificationApiModel_1 = require("./startVerificationApiModel");
const startVerificationResult_1 = require("./startVerificationResult");
const tFSIntegrationInfoModel_1 = require("./tFSIntegrationInfoModel");
const technologyApiModel_1 = require("./technologyApiModel");
const technologyListApiResult_1 = require("./technologyListApiResult");
const testScanProfileCredentialsRequestModel_1 = require("./testScanProfileCredentialsRequestModel");
const threeLeggedFields_1 = require("./threeLeggedFields");
const timezoneApiModel_1 = require("./timezoneApiModel");
const trelloBoard_1 = require("./trelloBoard");
const trelloIntegrationInfoModel_1 = require("./trelloIntegrationInfoModel");
const trelloLabel_1 = require("./trelloLabel");
const trelloList_1 = require("./trelloList");
const trelloMember_1 = require("./trelloMember");
const unfuddleIntegrationInfoModel_1 = require("./unfuddleIntegrationInfoModel");
const updateScanNotificationApiModel_1 = require("./updateScanNotificationApiModel");
const updateScanPolicySettingModel_1 = require("./updateScanPolicySettingModel");
const updateScheduledIncrementalScanApiModel_1 = require("./updateScheduledIncrementalScanApiModel");
const updateScheduledScanApiModel_1 = require("./updateScheduledScanApiModel");
const updateScheduledScanModel_1 = require("./updateScheduledScanModel");
const updateUserApiModel_1 = require("./updateUserApiModel");
const updateWebsiteApiModel_1 = require("./updateWebsiteApiModel");
const updateWebsiteGroupApiModel_1 = require("./updateWebsiteGroupApiModel");
const urlRewriteExcludedPathModel_1 = require("./urlRewriteExcludedPathModel");
const urlRewriteRuleModel_1 = require("./urlRewriteRuleModel");
const urlRewriteSetting_1 = require("./urlRewriteSetting");
const userApiModel_1 = require("./userApiModel");
const userApiTokenModel_1 = require("./userApiTokenModel");
const userHealthCheckApiModel_1 = require("./userHealthCheckApiModel");
const userListApiResult_1 = require("./userListApiResult");
const vcsCommitInfo_1 = require("./vcsCommitInfo");
const verifyApiModel_1 = require("./verifyApiModel");
const versionIssue_1 = require("./versionIssue");
const vulnerabilityClassification_1 = require("./vulnerabilityClassification");
const vulnerabilityContentApiModel_1 = require("./vulnerabilityContentApiModel");
const vulnerabilityModel_1 = require("./vulnerabilityModel");
const vulnerabilityTemplate_1 = require("./vulnerabilityTemplate");
const vulnerabilityTemplateCvss31Vector_1 = require("./vulnerabilityTemplateCvss31Vector");
const vulnerabilityTemplateCvssVector_1 = require("./vulnerabilityTemplateCvssVector");
const webStorageSetting_1 = require("./webStorageSetting");
const webhookIntegrationInfoModel_1 = require("./webhookIntegrationInfoModel");
const websiteApiModel_1 = require("./websiteApiModel");
const websiteGroupApiModel_1 = require("./websiteGroupApiModel");
const websiteGroupListApiResult_1 = require("./websiteGroupListApiResult");
const websiteGroupModel_1 = require("./websiteGroupModel");
const websiteListApiResult_1 = require("./websiteListApiResult");
const youTrackIntegrationInfoModel_1 = require("./youTrackIntegrationInfoModel");
const zapierIntegrationInfoModel_1 = require("./zapierIntegrationInfoModel");
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
let enumsMap = {
    "AgentListApiModel.StateEnum": agentListApiModel_1.AgentListApiModel.StateEnum,
    "ApiFileModel.ImporterTypeEnum": apiFileModel_1.ApiFileModel.ImporterTypeEnum,
    "ApiScanStatusModel.StateEnum": apiScanStatusModel_1.ApiScanStatusModel.StateEnum,
    "AsanaIntegrationInfoModel.TypeEnum": asanaIntegrationInfoModel_1.AsanaIntegrationInfoModel.TypeEnum,
    "AuthVerificationApiResult.LogoutSignatureTypeEnum": authVerificationApiResult_1.AuthVerificationApiResult.LogoutSignatureTypeEnum,
    "AzureDevOpsIntegrationInfoModel.TypeEnum": azureDevOpsIntegrationInfoModel_1.AzureDevOpsIntegrationInfoModel.TypeEnum,
    "BasicAuthenticationCredentialApiModel.AuthenticationTypeEnum": basicAuthenticationCredentialApiModel_1.BasicAuthenticationCredentialApiModel.AuthenticationTypeEnum,
    "BasicAuthenticationCredentialModel.AuthenticationTypeEnum": basicAuthenticationCredentialModel_1.BasicAuthenticationCredentialModel.AuthenticationTypeEnum,
    "BitbucketIntegrationInfoModel.TypeEnum": bitbucketIntegrationInfoModel_1.BitbucketIntegrationInfoModel.TypeEnum,
    "BugzillaIntegrationInfoModel.TypeEnum": bugzillaIntegrationInfoModel_1.BugzillaIntegrationInfoModel.TypeEnum,
    "ClubhouseIntegrationInfoModel.ClubhouseStoryTypeEnum": clubhouseIntegrationInfoModel_1.ClubhouseIntegrationInfoModel.ClubhouseStoryTypeEnum,
    "ClubhouseIntegrationInfoModel.TypeEnum": clubhouseIntegrationInfoModel_1.ClubhouseIntegrationInfoModel.TypeEnum,
    "CustomHttpHeaderSetting.AttackModeEnum": customHttpHeaderSetting_1.CustomHttpHeaderSetting.AttackModeEnum,
    "CvssScoreValue.SeverityEnum": cvssScoreValue_1.CvssScoreValue.SeverityEnum,
    "CyberArkVaultIntegrationInfoModel.TypeEnum": cyberArkVaultIntegrationInfoModel_1.CyberArkVaultIntegrationInfoModel.TypeEnum,
    "DiscoveryApiModel.StatusEnum": discoveryApiModel_1.DiscoveryApiModel.StatusEnum,
    "ExtensionSettingModel.AttackOptionEnum": extensionSettingModel_1.ExtensionSettingModel.AttackOptionEnum,
    "ExtensionSettingModel.CrawlOptionEnum": extensionSettingModel_1.ExtensionSettingModel.CrawlOptionEnum,
    "FileCache.ImporterTypeEnum": fileCache_1.FileCache.ImporterTypeEnum,
    "FogBugzIntegrationInfoModel.TypeEnum": fogBugzIntegrationInfoModel_1.FogBugzIntegrationInfoModel.TypeEnum,
    "FormAuthenticationHashicorpVaultSetting.VersionEnum": formAuthenticationHashicorpVaultSetting_1.FormAuthenticationHashicorpVaultSetting.VersionEnum,
    "FormAuthenticationPersona.OtpTypeEnum": formAuthenticationPersona_1.FormAuthenticationPersona.OtpTypeEnum,
    "FormAuthenticationPersona.DigitEnum": formAuthenticationPersona_1.FormAuthenticationPersona.DigitEnum,
    "FormAuthenticationPersona.AlgorithmEnum": formAuthenticationPersona_1.FormAuthenticationPersona.AlgorithmEnum,
    "FormAuthenticationPersona.FormAuthTypeEnum": formAuthenticationPersona_1.FormAuthenticationPersona.FormAuthTypeEnum,
    "FormAuthenticationPersona.VersionEnum": formAuthenticationPersona_1.FormAuthenticationPersona.VersionEnum,
    "FormAuthenticationSettingApiModel.FormAuthTypeEnum": formAuthenticationSettingApiModel_1.FormAuthenticationSettingApiModel.FormAuthTypeEnum,
    "FormValueSettingModel.MatchEnum": formValueSettingModel_1.FormValueSettingModel.MatchEnum,
    "FormValueSettingModel.MatchTargetEnum": formValueSettingModel_1.FormValueSettingModel.MatchTargetEnum,
    "FormValueSettingModel.MatchTargetValueEnum": formValueSettingModel_1.FormValueSettingModel.MatchTargetValueEnum,
    "FreshserviceIntegrationInfoModel.TypeEnum": freshserviceIntegrationInfoModel_1.FreshserviceIntegrationInfoModel.TypeEnum,
    "GitHubIntegrationInfoModel.TypeEnum": gitHubIntegrationInfoModel_1.GitHubIntegrationInfoModel.TypeEnum,
    "GitLabIntegrationInfoModel.TypeEnum": gitLabIntegrationInfoModel_1.GitLabIntegrationInfoModel.TypeEnum,
    "HashicorpVaultIntegrationInfoModel.TypeEnum": hashicorpVaultIntegrationInfoModel_1.HashicorpVaultIntegrationInfoModel.TypeEnum,
    "IgnorePatternSettingModel.ParameterTypeEnum": ignorePatternSettingModel_1.IgnorePatternSettingModel.ParameterTypeEnum,
    "IntegrationUserMappingItemModel.IntegrationSystemEnum": integrationUserMappingItemModel_1.IntegrationUserMappingItemModel.IntegrationSystemEnum,
    "IntegrationUserMappingItemModel.ResultEnum": integrationUserMappingItemModel_1.IntegrationUserMappingItemModel.ResultEnum,
    "IssueApiModel.SeverityEnum": issueApiModel_1.IssueApiModel.SeverityEnum,
    "IssueApiModel.TypeEnum": issueApiModel_1.IssueApiModel.TypeEnum,
    "IssueReportFilterApiModel.CsvSeparatorEnum": issueReportFilterApiModel_1.IssueReportFilterApiModel.CsvSeparatorEnum,
    "IssueReportFilterApiModel.SeverityEnum": issueReportFilterApiModel_1.IssueReportFilterApiModel.SeverityEnum,
    "IssueRequestContentParametersApiModel.InputTypeEnum": issueRequestContentParametersApiModel_1.IssueRequestContentParametersApiModel.InputTypeEnum,
    "JiraIntegrationInfoModel.ReopenStatusJiraEnum": jiraIntegrationInfoModel_1.JiraIntegrationInfoModel.ReopenStatusJiraEnum,
    "JiraIntegrationInfoModel.TypeEnum": jiraIntegrationInfoModel_1.JiraIntegrationInfoModel.TypeEnum,
    "JiraIntegrationInfoModel.TemplateTypeEnum": jiraIntegrationInfoModel_1.JiraIntegrationInfoModel.TemplateTypeEnum,
    "JiraIntegrationInfoModel.EpicSelectionTypeEnum": jiraIntegrationInfoModel_1.JiraIntegrationInfoModel.EpicSelectionTypeEnum,
    "KafkaIntegrationInfoModel.DataSerializationEnum": kafkaIntegrationInfoModel_1.KafkaIntegrationInfoModel.DataSerializationEnum,
    "KafkaIntegrationInfoModel.TypeEnum": kafkaIntegrationInfoModel_1.KafkaIntegrationInfoModel.TypeEnum,
    "KennaIntegrationInfoModel.AssetApplicationIdentifierTypeEnum": kennaIntegrationInfoModel_1.KennaIntegrationInfoModel.AssetApplicationIdentifierTypeEnum,
    "KennaIntegrationInfoModel.TypeEnum": kennaIntegrationInfoModel_1.KennaIntegrationInfoModel.TypeEnum,
    "MattermostIntegrationInfoModel.TypeEnum": mattermostIntegrationInfoModel_1.MattermostIntegrationInfoModel.TypeEnum,
    "MicrosoftTeamsIntegrationInfoModel.TypeEnum": microsoftTeamsIntegrationInfoModel_1.MicrosoftTeamsIntegrationInfoModel.TypeEnum,
    "NewGroupScanApiModel.AuthenticationProfileOptionEnum": newGroupScanApiModel_1.NewGroupScanApiModel.AuthenticationProfileOptionEnum,
    "NewScanNotificationApiModel.EventEnum": newScanNotificationApiModel_1.NewScanNotificationApiModel.EventEnum,
    "NewScanNotificationApiModel.SeverityEnum": newScanNotificationApiModel_1.NewScanNotificationApiModel.SeverityEnum,
    "NewScanNotificationApiModel.StateEnum": newScanNotificationApiModel_1.NewScanNotificationApiModel.StateEnum,
    "NewScanNotificationApiModel.ScopeEnum": newScanNotificationApiModel_1.NewScanNotificationApiModel.ScopeEnum,
    "NewScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum": newScanNotificationRecipientApiModel_1.NewScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum,
    "NewScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum": newScanNotificationRecipientApiModel_1.NewScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum,
    "NewScanTaskApiModel.DisallowedHttpMethodsEnum": newScanTaskApiModel_1.NewScanTaskApiModel.DisallowedHttpMethodsEnum,
    "NewScanTaskApiModel.AuthenticationProfileOptionEnum": newScanTaskApiModel_1.NewScanTaskApiModel.AuthenticationProfileOptionEnum,
    "NewScanTaskApiModel.ScopeEnum": newScanTaskApiModel_1.NewScanTaskApiModel.ScopeEnum,
    "NewScanTaskApiModel.UrlRewriteModeEnum": newScanTaskApiModel_1.NewScanTaskApiModel.UrlRewriteModeEnum,
    "NewScheduledIncrementalScanApiModel.ScheduleRunTypeEnum": newScheduledIncrementalScanApiModel_1.NewScheduledIncrementalScanApiModel.ScheduleRunTypeEnum,
    "NewScheduledScanApiModel.ScheduleRunTypeEnum": newScheduledScanApiModel_1.NewScheduledScanApiModel.ScheduleRunTypeEnum,
    "NewScheduledScanApiModel.DisallowedHttpMethodsEnum": newScheduledScanApiModel_1.NewScheduledScanApiModel.DisallowedHttpMethodsEnum,
    "NewScheduledScanApiModel.AuthenticationProfileOptionEnum": newScheduledScanApiModel_1.NewScheduledScanApiModel.AuthenticationProfileOptionEnum,
    "NewScheduledScanApiModel.ScopeEnum": newScheduledScanApiModel_1.NewScheduledScanApiModel.ScopeEnum,
    "NewScheduledScanApiModel.UrlRewriteModeEnum": newScheduledScanApiModel_1.NewScheduledScanApiModel.UrlRewriteModeEnum,
    "NewScheduledWithProfileApiModel.ScheduleRunTypeEnum": newScheduledWithProfileApiModel_1.NewScheduledWithProfileApiModel.ScheduleRunTypeEnum,
    "NewWebsiteApiModel.AgentModeEnum": newWebsiteApiModel_1.NewWebsiteApiModel.AgentModeEnum,
    "NewWebsiteApiModel.LicenseTypeEnum": newWebsiteApiModel_1.NewWebsiteApiModel.LicenseTypeEnum,
    "NotificationIntegrationCustomFieldModel.InputTypeEnum": notificationIntegrationCustomFieldModel_1.NotificationIntegrationCustomFieldModel.InputTypeEnum,
    "OAuth2SettingApiModel.FlowTypeEnum": oAuth2SettingApiModel_1.OAuth2SettingApiModel.FlowTypeEnum,
    "OAuth2SettingApiModel.AuthenticationTypeEnum": oAuth2SettingApiModel_1.OAuth2SettingApiModel.AuthenticationTypeEnum,
    "OAuth2SettingModel.SelectedFlowTypeEnum": oAuth2SettingModel_1.OAuth2SettingModel.SelectedFlowTypeEnum,
    "OAuth2SettingModel.SelectedAuthenticationTypeEnum": oAuth2SettingModel_1.OAuth2SettingModel.SelectedAuthenticationTypeEnum,
    "OtpSettings.OtpTypeEnum": otpSettings_1.OtpSettings.OtpTypeEnum,
    "OtpSettings.DigitEnum": otpSettings_1.OtpSettings.DigitEnum,
    "OtpSettings.AlgorithmEnum": otpSettings_1.OtpSettings.AlgorithmEnum,
    "PagerDutyIntegrationInfoModel.ServiceTypeEnum": pagerDutyIntegrationInfoModel_1.PagerDutyIntegrationInfoModel.ServiceTypeEnum,
    "PagerDutyIntegrationInfoModel.TypeEnum": pagerDutyIntegrationInfoModel_1.PagerDutyIntegrationInfoModel.TypeEnum,
    "PagerDutyIntegrationInfoModel.UrgencyEnum": pagerDutyIntegrationInfoModel_1.PagerDutyIntegrationInfoModel.UrgencyEnum,
    "PciScanTaskViewModel.ScanStateEnum": pciScanTaskViewModel_1.PciScanTaskViewModel.ScanStateEnum,
    "PciScanTaskViewModel.ComplianceStatusEnum": pciScanTaskViewModel_1.PciScanTaskViewModel.ComplianceStatusEnum,
    "PivotalTrackerIntegrationInfoModel.TypeEnum": pivotalTrackerIntegrationInfoModel_1.PivotalTrackerIntegrationInfoModel.TypeEnum,
    "PivotalTrackerIntegrationInfoModel.StoryTypeEnum": pivotalTrackerIntegrationInfoModel_1.PivotalTrackerIntegrationInfoModel.StoryTypeEnum,
    "RedmineIntegrationInfoModel.TypeEnum": redmineIntegrationInfoModel_1.RedmineIntegrationInfoModel.TypeEnum,
    "SaveScanProfileApiModel.CreateTypeEnum": saveScanProfileApiModel_1.SaveScanProfileApiModel.CreateTypeEnum,
    "SaveScanProfileApiModel.DisallowedHttpMethodsEnum": saveScanProfileApiModel_1.SaveScanProfileApiModel.DisallowedHttpMethodsEnum,
    "SaveScanProfileApiModel.AuthenticationProfileOptionEnum": saveScanProfileApiModel_1.SaveScanProfileApiModel.AuthenticationProfileOptionEnum,
    "SaveScanProfileApiModel.ScopeEnum": saveScanProfileApiModel_1.SaveScanProfileApiModel.ScopeEnum,
    "SaveScanProfileApiModel.UrlRewriteModeEnum": saveScanProfileApiModel_1.SaveScanProfileApiModel.UrlRewriteModeEnum,
    "ScanCustomReportApiModel.ReportFormatEnum": scanCustomReportApiModel_1.ScanCustomReportApiModel.ReportFormatEnum,
    "ScanNotificationApiModel.EventEnum": scanNotificationApiModel_1.ScanNotificationApiModel.EventEnum,
    "ScanNotificationApiModel.SeverityEnum": scanNotificationApiModel_1.ScanNotificationApiModel.SeverityEnum,
    "ScanNotificationApiModel.StateEnum": scanNotificationApiModel_1.ScanNotificationApiModel.StateEnum,
    "ScanNotificationApiModel.ScopeEnum": scanNotificationApiModel_1.ScanNotificationApiModel.ScopeEnum,
    "ScanNotificationIntegrationViewModel.CategoryEnum": scanNotificationIntegrationViewModel_1.ScanNotificationIntegrationViewModel.CategoryEnum,
    "ScanNotificationIntegrationViewModel.TypeEnum": scanNotificationIntegrationViewModel_1.ScanNotificationIntegrationViewModel.TypeEnum,
    "ScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum": scanNotificationRecipientApiModel_1.ScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum,
    "ScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum": scanNotificationRecipientApiModel_1.ScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum,
    "ScanPolicyOptimizerOptions.AppServerEnum": scanPolicyOptimizerOptions_1.ScanPolicyOptimizerOptions.AppServerEnum,
    "ScanPolicyOptimizerOptions.DatabaseServerEnum": scanPolicyOptimizerOptions_1.ScanPolicyOptimizerOptions.DatabaseServerEnum,
    "ScanPolicyOptimizerOptions.DomParserPresetEnum": scanPolicyOptimizerOptions_1.ScanPolicyOptimizerOptions.DomParserPresetEnum,
    "ScanPolicyOptimizerOptions.OperatingSystemEnum": scanPolicyOptimizerOptions_1.ScanPolicyOptimizerOptions.OperatingSystemEnum,
    "ScanPolicyOptimizerOptions.SuggestionStatusEnum": scanPolicyOptimizerOptions_1.ScanPolicyOptimizerOptions.SuggestionStatusEnum,
    "ScanPolicyOptimizerOptions.WebServerEnum": scanPolicyOptimizerOptions_1.ScanPolicyOptimizerOptions.WebServerEnum,
    "ScanReportApiModel.ContentFormatEnum": scanReportApiModel_1.ScanReportApiModel.ContentFormatEnum,
    "ScanReportApiModel.FormatEnum": scanReportApiModel_1.ScanReportApiModel.FormatEnum,
    "ScanReportApiModel.TypeEnum": scanReportApiModel_1.ScanReportApiModel.TypeEnum,
    "ScanTaskModel.AuthenticationProfileOptionEnum": scanTaskModel_1.ScanTaskModel.AuthenticationProfileOptionEnum,
    "ScanTaskModel.ScopeEnum": scanTaskModel_1.ScanTaskModel.ScopeEnum,
    "ScanTaskModel.UrlRewriteModeEnum": scanTaskModel_1.ScanTaskModel.UrlRewriteModeEnum,
    "ScanTaskModel.FailureReasonEnum": scanTaskModel_1.ScanTaskModel.FailureReasonEnum,
    "ScanTaskModel.GlobalThreatLevelEnum": scanTaskModel_1.ScanTaskModel.GlobalThreatLevelEnum,
    "ScanTaskModel.PhaseEnum": scanTaskModel_1.ScanTaskModel.PhaseEnum,
    "ScanTaskModel.ScanTypeEnum": scanTaskModel_1.ScanTaskModel.ScanTypeEnum,
    "ScanTaskModel.StateEnum": scanTaskModel_1.ScanTaskModel.StateEnum,
    "ScanTaskModel.ThreatLevelEnum": scanTaskModel_1.ScanTaskModel.ThreatLevelEnum,
    "ScanTimeWindowItemModel.DayEnum": scanTimeWindowItemModel_1.ScanTimeWindowItemModel.DayEnum,
    "ScanTimeWindowItemViewModel.DayEnum": scanTimeWindowItemViewModel_1.ScanTimeWindowItemViewModel.DayEnum,
    "ScanTimeWindowViewModel.ScanCreateTypeEnum": scanTimeWindowViewModel_1.ScanTimeWindowViewModel.ScanCreateTypeEnum,
    "ScheduledScanModel.LastExecutionStatusEnum": scheduledScanModel_1.ScheduledScanModel.LastExecutionStatusEnum,
    "ScheduledScanModel.ScanTypeEnum": scheduledScanModel_1.ScheduledScanModel.ScanTypeEnum,
    "ScheduledScanModel.ScheduleRunTypeEnum": scheduledScanModel_1.ScheduledScanModel.ScheduleRunTypeEnum,
    "ScheduledScanModel.CustomScriptTemplateTypeEnum": scheduledScanModel_1.ScheduledScanModel.CustomScriptTemplateTypeEnum,
    "ScheduledScanModel.CreateTypeEnum": scheduledScanModel_1.ScheduledScanModel.CreateTypeEnum,
    "ScheduledScanRecurrenceApiModel.RepeatTypeEnum": scheduledScanRecurrenceApiModel_1.ScheduledScanRecurrenceApiModel.RepeatTypeEnum,
    "ScheduledScanRecurrenceApiModel.EndingTypeEnum": scheduledScanRecurrenceApiModel_1.ScheduledScanRecurrenceApiModel.EndingTypeEnum,
    "ScheduledScanRecurrenceApiModel.DaysOfWeekEnum": scheduledScanRecurrenceApiModel_1.ScheduledScanRecurrenceApiModel.DaysOfWeekEnum,
    "ScheduledScanRecurrenceApiModel.MonthsOfYearEnum": scheduledScanRecurrenceApiModel_1.ScheduledScanRecurrenceApiModel.MonthsOfYearEnum,
    "ScheduledScanRecurrenceApiModel.OrdinalEnum": scheduledScanRecurrenceApiModel_1.ScheduledScanRecurrenceApiModel.OrdinalEnum,
    "ScheduledScanRecurrenceApiModel.DayOfWeekEnum": scheduledScanRecurrenceApiModel_1.ScheduledScanRecurrenceApiModel.DayOfWeekEnum,
    "ScheduledScanRecurrenceViewModel.RepeatTypeEnum": scheduledScanRecurrenceViewModel_1.ScheduledScanRecurrenceViewModel.RepeatTypeEnum,
    "ScheduledScanRecurrenceViewModel.EndingTypeEnum": scheduledScanRecurrenceViewModel_1.ScheduledScanRecurrenceViewModel.EndingTypeEnum,
    "ScheduledScanRecurrenceViewModel.DaysOfWeekEnum": scheduledScanRecurrenceViewModel_1.ScheduledScanRecurrenceViewModel.DaysOfWeekEnum,
    "ScheduledScanRecurrenceViewModel.MonthsOfYearEnum": scheduledScanRecurrenceViewModel_1.ScheduledScanRecurrenceViewModel.MonthsOfYearEnum,
    "ScheduledScanRecurrenceViewModel.OrdinalEnum": scheduledScanRecurrenceViewModel_1.ScheduledScanRecurrenceViewModel.OrdinalEnum,
    "ScheduledScanRecurrenceViewModel.DayOfWeekEnum": scheduledScanRecurrenceViewModel_1.ScheduledScanRecurrenceViewModel.DayOfWeekEnum,
    "ScopeSetting.DisallowedHttpMethodsEnum": scopeSetting_1.ScopeSetting.DisallowedHttpMethodsEnum,
    "ScopeSetting.ScopeEnum": scopeSetting_1.ScopeSetting.ScopeEnum,
    "SecurityCheckGroupModel.TypeEnum": securityCheckGroupModel_1.SecurityCheckGroupModel.TypeEnum,
    "SecurityCheckGroupModel.EngineGroupEnum": securityCheckGroupModel_1.SecurityCheckGroupModel.EngineGroupEnum,
    "ServiceNowIntegrationInfoModel.ServiceNowCategoryTypesEnum": serviceNowIntegrationInfoModel_1.ServiceNowIntegrationInfoModel.ServiceNowCategoryTypesEnum,
    "ServiceNowIntegrationInfoModel.ServiceNowReopenCategoryTypeEnum": serviceNowIntegrationInfoModel_1.ServiceNowIntegrationInfoModel.ServiceNowReopenCategoryTypeEnum,
    "ServiceNowIntegrationInfoModel.ServiceNowOnHoldReasonTypeEnum": serviceNowIntegrationInfoModel_1.ServiceNowIntegrationInfoModel.ServiceNowOnHoldReasonTypeEnum,
    "ServiceNowIntegrationInfoModel.ResolvedStatusServiceNowEnum": serviceNowIntegrationInfoModel_1.ServiceNowIntegrationInfoModel.ResolvedStatusServiceNowEnum,
    "ServiceNowIntegrationInfoModel.TypeEnum": serviceNowIntegrationInfoModel_1.ServiceNowIntegrationInfoModel.TypeEnum,
    "ServiceNowIntegrationInfoModel.TemplateTypeEnum": serviceNowIntegrationInfoModel_1.ServiceNowIntegrationInfoModel.TemplateTypeEnum,
    "SharkModel.SharkPlatformTypeEnum": sharkModel_1.SharkModel.SharkPlatformTypeEnum,
    "SlackIntegrationInfoModel.TypeEnum": slackIntegrationInfoModel_1.SlackIntegrationInfoModel.TypeEnum,
    "SslTlsSettingModel.ExternalDomainInvalidCertificateActionEnum": sslTlsSettingModel_1.SslTlsSettingModel.ExternalDomainInvalidCertificateActionEnum,
    "SslTlsSettingModel.TargetUrlInvalidCertificateActionEnum": sslTlsSettingModel_1.SslTlsSettingModel.TargetUrlInvalidCertificateActionEnum,
    "StartVerificationApiModel.VerificationMethodEnum": startVerificationApiModel_1.StartVerificationApiModel.VerificationMethodEnum,
    "StartVerificationResult.VerifyOwnershipResultEnum": startVerificationResult_1.StartVerificationResult.VerifyOwnershipResultEnum,
    "TFSIntegrationInfoModel.TypeEnum": tFSIntegrationInfoModel_1.TFSIntegrationInfoModel.TypeEnum,
    "TrelloIntegrationInfoModel.TypeEnum": trelloIntegrationInfoModel_1.TrelloIntegrationInfoModel.TypeEnum,
    "UnfuddleIntegrationInfoModel.TypeEnum": unfuddleIntegrationInfoModel_1.UnfuddleIntegrationInfoModel.TypeEnum,
    "UpdateScanNotificationApiModel.EventEnum": updateScanNotificationApiModel_1.UpdateScanNotificationApiModel.EventEnum,
    "UpdateScanNotificationApiModel.SeverityEnum": updateScanNotificationApiModel_1.UpdateScanNotificationApiModel.SeverityEnum,
    "UpdateScanNotificationApiModel.StateEnum": updateScanNotificationApiModel_1.UpdateScanNotificationApiModel.StateEnum,
    "UpdateScanNotificationApiModel.ScopeEnum": updateScanNotificationApiModel_1.UpdateScanNotificationApiModel.ScopeEnum,
    "UpdateScheduledIncrementalScanApiModel.ScheduleRunTypeEnum": updateScheduledIncrementalScanApiModel_1.UpdateScheduledIncrementalScanApiModel.ScheduleRunTypeEnum,
    "UpdateScheduledScanApiModel.ScheduleRunTypeEnum": updateScheduledScanApiModel_1.UpdateScheduledScanApiModel.ScheduleRunTypeEnum,
    "UpdateScheduledScanApiModel.DisallowedHttpMethodsEnum": updateScheduledScanApiModel_1.UpdateScheduledScanApiModel.DisallowedHttpMethodsEnum,
    "UpdateScheduledScanApiModel.AuthenticationProfileOptionEnum": updateScheduledScanApiModel_1.UpdateScheduledScanApiModel.AuthenticationProfileOptionEnum,
    "UpdateScheduledScanApiModel.ScopeEnum": updateScheduledScanApiModel_1.UpdateScheduledScanApiModel.ScopeEnum,
    "UpdateScheduledScanApiModel.UrlRewriteModeEnum": updateScheduledScanApiModel_1.UpdateScheduledScanApiModel.UrlRewriteModeEnum,
    "UpdateScheduledScanModel.ScanTypeEnum": updateScheduledScanModel_1.UpdateScheduledScanModel.ScanTypeEnum,
    "UpdateScheduledScanModel.ScheduleRunTypeEnum": updateScheduledScanModel_1.UpdateScheduledScanModel.ScheduleRunTypeEnum,
    "UpdateScheduledScanModel.CustomScriptTemplateTypeEnum": updateScheduledScanModel_1.UpdateScheduledScanModel.CustomScriptTemplateTypeEnum,
    "UpdateScheduledScanModel.CreateTypeEnum": updateScheduledScanModel_1.UpdateScheduledScanModel.CreateTypeEnum,
    "UpdateUserApiModel.UserStateEnum": updateUserApiModel_1.UpdateUserApiModel.UserStateEnum,
    "UpdateWebsiteApiModel.DefaultProtocolEnum": updateWebsiteApiModel_1.UpdateWebsiteApiModel.DefaultProtocolEnum,
    "UpdateWebsiteApiModel.AgentModeEnum": updateWebsiteApiModel_1.UpdateWebsiteApiModel.AgentModeEnum,
    "UpdateWebsiteApiModel.LicenseTypeEnum": updateWebsiteApiModel_1.UpdateWebsiteApiModel.LicenseTypeEnum,
    "UrlRewriteSetting.UrlRewriteModeEnum": urlRewriteSetting_1.UrlRewriteSetting.UrlRewriteModeEnum,
    "UserApiModel.RoleEnum": userApiModel_1.UserApiModel.RoleEnum,
    "UserApiModel.UserStateEnum": userApiModel_1.UserApiModel.UserStateEnum,
    "VcsCommitInfo.IntegrationSystemEnum": vcsCommitInfo_1.VcsCommitInfo.IntegrationSystemEnum,
    "VerifyApiModel.VerificationMethodEnum": verifyApiModel_1.VerifyApiModel.VerificationMethodEnum,
    "VersionIssue.SeverityEnum": versionIssue_1.VersionIssue.SeverityEnum,
    "VulnerabilityModel.TypeEnum": vulnerabilityModel_1.VulnerabilityModel.TypeEnum,
    "VulnerabilityTemplate.TypeEnum": vulnerabilityTemplate_1.VulnerabilityTemplate.TypeEnum,
    "VulnerabilityTemplate.SeverityEnum": vulnerabilityTemplate_1.VulnerabilityTemplate.SeverityEnum,
    "VulnerabilityTemplate.OrderEnum": vulnerabilityTemplate_1.VulnerabilityTemplate.OrderEnum,
    "WebStorageSetting.TypeEnum": webStorageSetting_1.WebStorageSetting.TypeEnum,
    "WebhookIntegrationInfoModel.HttpMethodTypeEnum": webhookIntegrationInfoModel_1.WebhookIntegrationInfoModel.HttpMethodTypeEnum,
    "WebhookIntegrationInfoModel.ParameterTypeEnum": webhookIntegrationInfoModel_1.WebhookIntegrationInfoModel.ParameterTypeEnum,
    "WebhookIntegrationInfoModel.TypeEnum": webhookIntegrationInfoModel_1.WebhookIntegrationInfoModel.TypeEnum,
    "WebsiteApiModel.LicenseTypeEnum": websiteApiModel_1.WebsiteApiModel.LicenseTypeEnum,
    "WebsiteApiModel.AgentModeEnum": websiteApiModel_1.WebsiteApiModel.AgentModeEnum,
    "YouTrackIntegrationInfoModel.TypeEnum": youTrackIntegrationInfoModel_1.YouTrackIntegrationInfoModel.TypeEnum,
    "ZapierIntegrationInfoModel.TypeEnum": zapierIntegrationInfoModel_1.ZapierIntegrationInfoModel.TypeEnum,
};
let typeMap = {
    "AccessTokenTableModel": accessTokenTableModel_1.AccessTokenTableModel,
    "AccountLicenseApiModel": accountLicenseApiModel_1.AccountLicenseApiModel,
    "AdditionalWebsiteModel": additionalWebsiteModel_1.AdditionalWebsiteModel,
    "AdditionalWebsitesSettingModel": additionalWebsitesSettingModel_1.AdditionalWebsitesSettingModel,
    "AgentGroupApiDeleteModel": agentGroupApiDeleteModel_1.AgentGroupApiDeleteModel,
    "AgentGroupApiModel": agentGroupApiModel_1.AgentGroupApiModel,
    "AgentGroupApiNewModel": agentGroupApiNewModel_1.AgentGroupApiNewModel,
    "AgentGroupApiUpdateModel": agentGroupApiUpdateModel_1.AgentGroupApiUpdateModel,
    "AgentGroupModel": agentGroupModel_1.AgentGroupModel,
    "AgentGroupsListApiResult": agentGroupsListApiResult_1.AgentGroupsListApiResult,
    "AgentListApiModel": agentListApiModel_1.AgentListApiModel,
    "AgentListApiResult": agentListApiResult_1.AgentListApiResult,
    "AgentSelectionModel": agentSelectionModel_1.AgentSelectionModel,
    "AgentStatusModel": agentStatusModel_1.AgentStatusModel,
    "ApiFileModel": apiFileModel_1.ApiFileModel,
    "ApiScanStatusModel": apiScanStatusModel_1.ApiScanStatusModel,
    "AsanaIntegrationInfoModel": asanaIntegrationInfoModel_1.AsanaIntegrationInfoModel,
    "AsanaProject": asanaProject_1.AsanaProject,
    "AsanaTag": asanaTag_1.AsanaTag,
    "AsanaUser": asanaUser_1.AsanaUser,
    "AsanaWorkspace": asanaWorkspace_1.AsanaWorkspace,
    "AttackingSettingModel": attackingSettingModel_1.AttackingSettingModel,
    "AuthVerificationApiResult": authVerificationApiResult_1.AuthVerificationApiResult,
    "AuthenticationProfileViewModel": authenticationProfileViewModel_1.AuthenticationProfileViewModel,
    "AuthorizationCodeTableModel": authorizationCodeTableModel_1.AuthorizationCodeTableModel,
    "AutoCompleteSettingModel": autoCompleteSettingModel_1.AutoCompleteSettingModel,
    "AzureDevOpsIntegrationInfoModel": azureDevOpsIntegrationInfoModel_1.AzureDevOpsIntegrationInfoModel,
    "BaseScanApiModel": baseScanApiModel_1.BaseScanApiModel,
    "BasicAuthenticationCredentialApiModel": basicAuthenticationCredentialApiModel_1.BasicAuthenticationCredentialApiModel,
    "BasicAuthenticationCredentialModel": basicAuthenticationCredentialModel_1.BasicAuthenticationCredentialModel,
    "BasicAuthenticationSettingApiModel": basicAuthenticationSettingApiModel_1.BasicAuthenticationSettingApiModel,
    "BasicAuthenticationSettingModel": basicAuthenticationSettingModel_1.BasicAuthenticationSettingModel,
    "BitbucketIntegrationInfoModel": bitbucketIntegrationInfoModel_1.BitbucketIntegrationInfoModel,
    "BruteForceSettingModel": bruteForceSettingModel_1.BruteForceSettingModel,
    "BugzillaIntegrationInfoModel": bugzillaIntegrationInfoModel_1.BugzillaIntegrationInfoModel,
    "ClientCertificateAuthenticationApiModel": clientCertificateAuthenticationApiModel_1.ClientCertificateAuthenticationApiModel,
    "ClientCertificateAuthenticationViewModel": clientCertificateAuthenticationViewModel_1.ClientCertificateAuthenticationViewModel,
    "ClubhouseIntegrationInfoModel": clubhouseIntegrationInfoModel_1.ClubhouseIntegrationInfoModel,
    "ContentTypeModel": contentTypeModel_1.ContentTypeModel,
    "ContentTypeTemplate": contentTypeTemplate_1.ContentTypeTemplate,
    "CrawlingSettingModel": crawlingSettingModel_1.CrawlingSettingModel,
    "CsrfSettingModel": csrfSettingModel_1.CsrfSettingModel,
    "Custom404SettingModel": custom404SettingModel_1.Custom404SettingModel,
    "CustomFieldModel": customFieldModel_1.CustomFieldModel,
    "CustomHttpHeaderModel": customHttpHeaderModel_1.CustomHttpHeaderModel,
    "CustomHttpHeaderSetting": customHttpHeaderSetting_1.CustomHttpHeaderSetting,
    "CustomScriptPageViewModel": customScriptPageViewModel_1.CustomScriptPageViewModel,
    "CustomTemplateContentModel": customTemplateContentModel_1.CustomTemplateContentModel,
    "CustomTemplateModel": customTemplateModel_1.CustomTemplateModel,
    "CvssMetricModel": cvssMetricModel_1.CvssMetricModel,
    "CvssScoreValue": cvssScoreValue_1.CvssScoreValue,
    "CyberArkVaultIntegrationInfoModel": cyberArkVaultIntegrationInfoModel_1.CyberArkVaultIntegrationInfoModel,
    "DeleteAgentModel": deleteAgentModel_1.DeleteAgentModel,
    "DeleteScanNotificationApiModel": deleteScanNotificationApiModel_1.DeleteScanNotificationApiModel,
    "DeleteWebsiteApiModel": deleteWebsiteApiModel_1.DeleteWebsiteApiModel,
    "DeleteWebsiteGroupApiModel": deleteWebsiteGroupApiModel_1.DeleteWebsiteGroupApiModel,
    "DiscoveryApiModel": discoveryApiModel_1.DiscoveryApiModel,
    "DiscoveryServiceListApiResult": discoveryServiceListApiResult_1.DiscoveryServiceListApiResult,
    "DiscoverySettingsApiModel": discoverySettingsApiModel_1.DiscoverySettingsApiModel,
    "EmailPatternSetting": emailPatternSetting_1.EmailPatternSetting,
    "ExcludeFilter": excludeFilter_1.ExcludeFilter,
    "ExcludedLinkModel": excludedLinkModel_1.ExcludedLinkModel,
    "ExcludedUsageTrackerModel": excludedUsageTrackerModel_1.ExcludedUsageTrackerModel,
    "ExtensionSettingModel": extensionSettingModel_1.ExtensionSettingModel,
    "FileCache": fileCache_1.FileCache,
    "FogBugzIntegrationInfoModel": fogBugzIntegrationInfoModel_1.FogBugzIntegrationInfoModel,
    "FormAuthenticationCustomScript": formAuthenticationCustomScript_1.FormAuthenticationCustomScript,
    "FormAuthenticationCyberArkVaultSetting": formAuthenticationCyberArkVaultSetting_1.FormAuthenticationCyberArkVaultSetting,
    "FormAuthenticationHashicorpVaultSetting": formAuthenticationHashicorpVaultSetting_1.FormAuthenticationHashicorpVaultSetting,
    "FormAuthenticationPersona": formAuthenticationPersona_1.FormAuthenticationPersona,
    "FormAuthenticationSettingApiModel": formAuthenticationSettingApiModel_1.FormAuthenticationSettingApiModel,
    "FormAuthenticationSettingModel": formAuthenticationSettingModel_1.FormAuthenticationSettingModel,
    "FormAuthenticationVerificationApiModel": formAuthenticationVerificationApiModel_1.FormAuthenticationVerificationApiModel,
    "FormValueSettingModel": formValueSettingModel_1.FormValueSettingModel,
    "FreshserviceEntity": freshserviceEntity_1.FreshserviceEntity,
    "FreshserviceIntegrationInfoModel": freshserviceIntegrationInfoModel_1.FreshserviceIntegrationInfoModel,
    "FreshserviceUser": freshserviceUser_1.FreshserviceUser,
    "GitHubIntegrationInfoModel": gitHubIntegrationInfoModel_1.GitHubIntegrationInfoModel,
    "GitLabIntegrationInfoModel": gitLabIntegrationInfoModel_1.GitLabIntegrationInfoModel,
    "HashicorpVaultIntegrationInfoModel": hashicorpVaultIntegrationInfoModel_1.HashicorpVaultIntegrationInfoModel,
    "HeaderAuthenticationModel": headerAuthenticationModel_1.HeaderAuthenticationModel,
    "HttpRequestSettingModel": httpRequestSettingModel_1.HttpRequestSettingModel,
    "IdNamePair": idNamePair_1.IdNamePair,
    "IgnorePatternSettingModel": ignorePatternSettingModel_1.IgnorePatternSettingModel,
    "ImportedLinksSetting": importedLinksSetting_1.ImportedLinksSetting,
    "IncrementalApiModel": incrementalApiModel_1.IncrementalApiModel,
    "IntegrationUserMappingItemModel": integrationUserMappingItemModel_1.IntegrationUserMappingItemModel,
    "IntegrationWizardResultModel": integrationWizardResultModel_1.IntegrationWizardResultModel,
    "IssueApiModel": issueApiModel_1.IssueApiModel,
    "IssueApiModelCvssVector": issueApiModelCvssVector_1.IssueApiModelCvssVector,
    "IssueApiResult": issueApiResult_1.IssueApiResult,
    "IssueApiUpdateModel": issueApiUpdateModel_1.IssueApiUpdateModel,
    "IssueHistoryApiModel": issueHistoryApiModel_1.IssueHistoryApiModel,
    "IssueReportFilterApiModel": issueReportFilterApiModel_1.IssueReportFilterApiModel,
    "IssueRequestContentParametersApiModel": issueRequestContentParametersApiModel_1.IssueRequestContentParametersApiModel,
    "JavaScriptSettingsModel": javaScriptSettingsModel_1.JavaScriptSettingsModel,
    "JiraIntegrationInfoModel": jiraIntegrationInfoModel_1.JiraIntegrationInfoModel,
    "KafkaIntegrationInfoModel": kafkaIntegrationInfoModel_1.KafkaIntegrationInfoModel,
    "KennaIntegrationInfoModel": kennaIntegrationInfoModel_1.KennaIntegrationInfoModel,
    "LicenseBaseModel": licenseBaseModel_1.LicenseBaseModel,
    "LogoutKeywordPatternModel": logoutKeywordPatternModel_1.LogoutKeywordPatternModel,
    "MattermostIntegrationInfoModel": mattermostIntegrationInfoModel_1.MattermostIntegrationInfoModel,
    "MicrosoftTeamsIntegrationInfoModel": microsoftTeamsIntegrationInfoModel_1.MicrosoftTeamsIntegrationInfoModel,
    "NameValuePair": nameValuePair_1.NameValuePair,
    "NewGroupScanApiModel": newGroupScanApiModel_1.NewGroupScanApiModel,
    "NewScanNotificationApiModel": newScanNotificationApiModel_1.NewScanNotificationApiModel,
    "NewScanNotificationRecipientApiModel": newScanNotificationRecipientApiModel_1.NewScanNotificationRecipientApiModel,
    "NewScanPolicySettingModel": newScanPolicySettingModel_1.NewScanPolicySettingModel,
    "NewScanTaskApiModel": newScanTaskApiModel_1.NewScanTaskApiModel,
    "NewScanTaskWithProfileApiModel": newScanTaskWithProfileApiModel_1.NewScanTaskWithProfileApiModel,
    "NewScheduledIncrementalScanApiModel": newScheduledIncrementalScanApiModel_1.NewScheduledIncrementalScanApiModel,
    "NewScheduledScanApiModel": newScheduledScanApiModel_1.NewScheduledScanApiModel,
    "NewScheduledWithProfileApiModel": newScheduledWithProfileApiModel_1.NewScheduledWithProfileApiModel,
    "NewUserApiModel": newUserApiModel_1.NewUserApiModel,
    "NewWebsiteApiModel": newWebsiteApiModel_1.NewWebsiteApiModel,
    "NewWebsiteGroupApiModel": newWebsiteGroupApiModel_1.NewWebsiteGroupApiModel,
    "NotificationIntegrationCustomFieldModel": notificationIntegrationCustomFieldModel_1.NotificationIntegrationCustomFieldModel,
    "NotificationPriorityPair": notificationPriorityPair_1.NotificationPriorityPair,
    "OAuth2SettingApiModel": oAuth2SettingApiModel_1.OAuth2SettingApiModel,
    "OAuth2SettingEndPointModel": oAuth2SettingEndPointModel_1.OAuth2SettingEndPointModel,
    "OAuth2SettingEndpoint": oAuth2SettingEndpoint_1.OAuth2SettingEndpoint,
    "OAuth2SettingModel": oAuth2SettingModel_1.OAuth2SettingModel,
    "OtpSettings": otpSettings_1.OtpSettings,
    "OutsiderRecipient": outsiderRecipient_1.OutsiderRecipient,
    "PagerDutyIntegrationInfoModel": pagerDutyIntegrationInfoModel_1.PagerDutyIntegrationInfoModel,
    "PciScanTaskViewModel": pciScanTaskViewModel_1.PciScanTaskViewModel,
    "PivotalTrackerIntegrationInfoModel": pivotalTrackerIntegrationInfoModel_1.PivotalTrackerIntegrationInfoModel,
    "PreRequestScriptSettingModel": preRequestScriptSettingModel_1.PreRequestScriptSettingModel,
    "ProxySettingsModel": proxySettingsModel_1.ProxySettingsModel,
    "RedmineIntegrationInfoModel": redmineIntegrationInfoModel_1.RedmineIntegrationInfoModel,
    "ReducedScanTaskProfile": reducedScanTaskProfile_1.ReducedScanTaskProfile,
    "ResponseFields": responseFields_1.ResponseFields,
    "SaveScanProfileApiModel": saveScanProfileApiModel_1.SaveScanProfileApiModel,
    "ScanCustomReportApiModel": scanCustomReportApiModel_1.ScanCustomReportApiModel,
    "ScanNotificationApiModel": scanNotificationApiModel_1.ScanNotificationApiModel,
    "ScanNotificationIntegrationViewModel": scanNotificationIntegrationViewModel_1.ScanNotificationIntegrationViewModel,
    "ScanNotificationListApiResult": scanNotificationListApiResult_1.ScanNotificationListApiResult,
    "ScanNotificationRecipientApiModel": scanNotificationRecipientApiModel_1.ScanNotificationRecipientApiModel,
    "ScanNotificationRecipientUserApiModel": scanNotificationRecipientUserApiModel_1.ScanNotificationRecipientUserApiModel,
    "ScanNotificationScanTaskGroupApiModel": scanNotificationScanTaskGroupApiModel_1.ScanNotificationScanTaskGroupApiModel,
    "ScanPolicyListApiResult": scanPolicyListApiResult_1.ScanPolicyListApiResult,
    "ScanPolicyOptimizerOptions": scanPolicyOptimizerOptions_1.ScanPolicyOptimizerOptions,
    "ScanPolicyPatternModel": scanPolicyPatternModel_1.ScanPolicyPatternModel,
    "ScanPolicySettingApiModel": scanPolicySettingApiModel_1.ScanPolicySettingApiModel,
    "ScanPolicySettingItemApiModel": scanPolicySettingItemApiModel_1.ScanPolicySettingItemApiModel,
    "ScanProfilesListApiResult": scanProfilesListApiResult_1.ScanProfilesListApiResult,
    "ScanReportApiModel": scanReportApiModel_1.ScanReportApiModel,
    "ScanTaskListApiResult": scanTaskListApiResult_1.ScanTaskListApiResult,
    "ScanTaskModel": scanTaskModel_1.ScanTaskModel,
    "ScanTimeWindowItemModel": scanTimeWindowItemModel_1.ScanTimeWindowItemModel,
    "ScanTimeWindowItemViewModel": scanTimeWindowItemViewModel_1.ScanTimeWindowItemViewModel,
    "ScanTimeWindowModel": scanTimeWindowModel_1.ScanTimeWindowModel,
    "ScanTimeWindowViewModel": scanTimeWindowViewModel_1.ScanTimeWindowViewModel,
    "ScheduledScanListApiResult": scheduledScanListApiResult_1.ScheduledScanListApiResult,
    "ScheduledScanModel": scheduledScanModel_1.ScheduledScanModel,
    "ScheduledScanRecurrenceApiModel": scheduledScanRecurrenceApiModel_1.ScheduledScanRecurrenceApiModel,
    "ScheduledScanRecurrenceViewModel": scheduledScanRecurrenceViewModel_1.ScheduledScanRecurrenceViewModel,
    "ScopeSetting": scopeSetting_1.ScopeSetting,
    "ScopeSettingModel": scopeSettingModel_1.ScopeSettingModel,
    "SecurityCheckGroupModel": securityCheckGroupModel_1.SecurityCheckGroupModel,
    "SecurityCheckGroupParentModel": securityCheckGroupParentModel_1.SecurityCheckGroupParentModel,
    "SecurityCheckSetting": securityCheckSetting_1.SecurityCheckSetting,
    "SelectOptionModel": selectOptionModel_1.SelectOptionModel,
    "SendVerificationEmailModel": sendVerificationEmailModel_1.SendVerificationEmailModel,
    "SensitiveKeywordSettingModel": sensitiveKeywordSettingModel_1.SensitiveKeywordSettingModel,
    "ServiceNowIntegrationInfoModel": serviceNowIntegrationInfoModel_1.ServiceNowIntegrationInfoModel,
    "SharkModel": sharkModel_1.SharkModel,
    "SlackIntegrationInfoModel": slackIntegrationInfoModel_1.SlackIntegrationInfoModel,
    "SslTlsSettingModel": sslTlsSettingModel_1.SslTlsSettingModel,
    "StartVerificationApiModel": startVerificationApiModel_1.StartVerificationApiModel,
    "StartVerificationResult": startVerificationResult_1.StartVerificationResult,
    "TFSIntegrationInfoModel": tFSIntegrationInfoModel_1.TFSIntegrationInfoModel,
    "TechnologyApiModel": technologyApiModel_1.TechnologyApiModel,
    "TechnologyListApiResult": technologyListApiResult_1.TechnologyListApiResult,
    "TestScanProfileCredentialsRequestModel": testScanProfileCredentialsRequestModel_1.TestScanProfileCredentialsRequestModel,
    "ThreeLeggedFields": threeLeggedFields_1.ThreeLeggedFields,
    "TimezoneApiModel": timezoneApiModel_1.TimezoneApiModel,
    "TrelloBoard": trelloBoard_1.TrelloBoard,
    "TrelloIntegrationInfoModel": trelloIntegrationInfoModel_1.TrelloIntegrationInfoModel,
    "TrelloLabel": trelloLabel_1.TrelloLabel,
    "TrelloList": trelloList_1.TrelloList,
    "TrelloMember": trelloMember_1.TrelloMember,
    "UnfuddleIntegrationInfoModel": unfuddleIntegrationInfoModel_1.UnfuddleIntegrationInfoModel,
    "UpdateScanNotificationApiModel": updateScanNotificationApiModel_1.UpdateScanNotificationApiModel,
    "UpdateScanPolicySettingModel": updateScanPolicySettingModel_1.UpdateScanPolicySettingModel,
    "UpdateScheduledIncrementalScanApiModel": updateScheduledIncrementalScanApiModel_1.UpdateScheduledIncrementalScanApiModel,
    "UpdateScheduledScanApiModel": updateScheduledScanApiModel_1.UpdateScheduledScanApiModel,
    "UpdateScheduledScanModel": updateScheduledScanModel_1.UpdateScheduledScanModel,
    "UpdateUserApiModel": updateUserApiModel_1.UpdateUserApiModel,
    "UpdateWebsiteApiModel": updateWebsiteApiModel_1.UpdateWebsiteApiModel,
    "UpdateWebsiteGroupApiModel": updateWebsiteGroupApiModel_1.UpdateWebsiteGroupApiModel,
    "UrlRewriteExcludedPathModel": urlRewriteExcludedPathModel_1.UrlRewriteExcludedPathModel,
    "UrlRewriteRuleModel": urlRewriteRuleModel_1.UrlRewriteRuleModel,
    "UrlRewriteSetting": urlRewriteSetting_1.UrlRewriteSetting,
    "UserApiModel": userApiModel_1.UserApiModel,
    "UserApiTokenModel": userApiTokenModel_1.UserApiTokenModel,
    "UserHealthCheckApiModel": userHealthCheckApiModel_1.UserHealthCheckApiModel,
    "UserListApiResult": userListApiResult_1.UserListApiResult,
    "VcsCommitInfo": vcsCommitInfo_1.VcsCommitInfo,
    "VerifyApiModel": verifyApiModel_1.VerifyApiModel,
    "VersionIssue": versionIssue_1.VersionIssue,
    "VulnerabilityClassification": vulnerabilityClassification_1.VulnerabilityClassification,
    "VulnerabilityContentApiModel": vulnerabilityContentApiModel_1.VulnerabilityContentApiModel,
    "VulnerabilityModel": vulnerabilityModel_1.VulnerabilityModel,
    "VulnerabilityTemplate": vulnerabilityTemplate_1.VulnerabilityTemplate,
    "VulnerabilityTemplateCvss31Vector": vulnerabilityTemplateCvss31Vector_1.VulnerabilityTemplateCvss31Vector,
    "VulnerabilityTemplateCvssVector": vulnerabilityTemplateCvssVector_1.VulnerabilityTemplateCvssVector,
    "WebStorageSetting": webStorageSetting_1.WebStorageSetting,
    "WebhookIntegrationInfoModel": webhookIntegrationInfoModel_1.WebhookIntegrationInfoModel,
    "WebsiteApiModel": websiteApiModel_1.WebsiteApiModel,
    "WebsiteGroupApiModel": websiteGroupApiModel_1.WebsiteGroupApiModel,
    "WebsiteGroupListApiResult": websiteGroupListApiResult_1.WebsiteGroupListApiResult,
    "WebsiteGroupModel": websiteGroupModel_1.WebsiteGroupModel,
    "WebsiteListApiResult": websiteListApiResult_1.WebsiteListApiResult,
    "YouTrackIntegrationInfoModel": youTrackIntegrationInfoModel_1.YouTrackIntegrationInfoModel,
    "ZapierIntegrationInfoModel": zapierIntegrationInfoModel_1.ZapierIntegrationInfoModel,
};
class ObjectSerializer {
    static findCorrectType(data, expectedType) {
        if (data == undefined) {
            return expectedType;
        }
        else if (primitives.indexOf(expectedType.toLowerCase()) !== -1) {
            return expectedType;
        }
        else if (expectedType === "Date") {
            return expectedType;
        }
        else {
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
            }
            else {
                if (data[discriminatorProperty]) {
                    var discriminatorType = data[discriminatorProperty];
                    if (typeMap[discriminatorType]) {
                        return discriminatorType; // use the type given in the discriminator
                    }
                    else {
                        return expectedType; // discriminator did not map to a type
                    }
                }
                else {
                    return expectedType; // discriminator was not present (or an empty string)
                }
            }
        }
    }
    static serialize(data, type) {
        if (data == undefined) {
            return data;
        }
        else if (primitives.indexOf(type.toLowerCase()) !== -1) {
            return data;
        }
        else if (type.lastIndexOf("Array<", 0) === 0) { // string.startsWith pre es6
            let subType = type.replace("Array<", ""); // Array<Type> => Type>
            subType = subType.substring(0, subType.length - 1); // Type> => Type
            let transformedData = [];
            for (let index = 0; index < data.length; index++) {
                let datum = data[index];
                transformedData.push(ObjectSerializer.serialize(datum, subType));
            }
            return transformedData;
        }
        else if (type === "Date") {
            return data.toISOString();
        }
        else {
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
            let instance = {};
            for (let index = 0; index < attributeTypes.length; index++) {
                let attributeType = attributeTypes[index];
                instance[attributeType.baseName] = ObjectSerializer.serialize(data[attributeType.name], attributeType.type);
            }
            return instance;
        }
    }
    static deserialize(data, type) {
        // polymorphism may change the actual type.
        type = ObjectSerializer.findCorrectType(data, type);
        if (data == undefined) {
            return data;
        }
        else if (primitives.indexOf(type.toLowerCase()) !== -1) {
            return data;
        }
        else if (type.lastIndexOf("Array<", 0) === 0) { // string.startsWith pre es6
            let subType = type.replace("Array<", ""); // Array<Type> => Type>
            subType = subType.substring(0, subType.length - 1); // Type> => Type
            let transformedData = [];
            for (let index = 0; index < data.length; index++) {
                let datum = data[index];
                transformedData.push(ObjectSerializer.deserialize(datum, subType));
            }
            return transformedData;
        }
        else if (type === "Date") {
            return new Date(data);
        }
        else {
            if (enumsMap[type]) { // is Enum
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
exports.ObjectSerializer = ObjectSerializer;
class HttpBasicAuth {
    constructor() {
        this.username = '';
        this.password = '';
    }
    applyToRequest(requestOptions) {
        requestOptions.auth = {
            username: this.username, password: this.password
        };
    }
}
exports.HttpBasicAuth = HttpBasicAuth;
class HttpBearerAuth {
    constructor() {
        this.accessToken = '';
    }
    applyToRequest(requestOptions) {
        if (requestOptions && requestOptions.headers) {
            const accessToken = typeof this.accessToken === 'function'
                ? this.accessToken()
                : this.accessToken;
            requestOptions.headers["Authorization"] = "Bearer " + accessToken;
        }
    }
}
exports.HttpBearerAuth = HttpBearerAuth;
class ApiKeyAuth {
    constructor(location, paramName) {
        this.location = location;
        this.paramName = paramName;
        this.apiKey = '';
    }
    applyToRequest(requestOptions) {
        if (this.location == "query") {
            requestOptions.qs[this.paramName] = this.apiKey;
        }
        else if (this.location == "header" && requestOptions && requestOptions.headers) {
            requestOptions.headers[this.paramName] = this.apiKey;
        }
        else if (this.location == 'cookie' && requestOptions && requestOptions.headers) {
            if (requestOptions.headers['Cookie']) {
                requestOptions.headers['Cookie'] += '; ' + this.paramName + '=' + encodeURIComponent(this.apiKey);
            }
            else {
                requestOptions.headers['Cookie'] = this.paramName + '=' + encodeURIComponent(this.apiKey);
            }
        }
    }
}
exports.ApiKeyAuth = ApiKeyAuth;
class OAuth {
    constructor() {
        this.accessToken = '';
    }
    applyToRequest(requestOptions) {
        if (requestOptions && requestOptions.headers) {
            requestOptions.headers["Authorization"] = "Bearer " + this.accessToken;
        }
    }
}
exports.OAuth = OAuth;
class VoidAuth {
    constructor() {
        this.username = '';
        this.password = '';
    }
    applyToRequest(_) {
        // Do nothing
    }
}
exports.VoidAuth = VoidAuth;
//# sourceMappingURL=models.js.map