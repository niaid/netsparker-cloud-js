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
/**
 *
 * @export
 * @interface AuditLogDto
 */
export interface AuditLogDto {
    /**
     *
     * @type {string}
     * @memberof AuditLogDto
     */
    accountId?: string;
    /**
     *
     * @type {Date}
     * @memberof AuditLogDto
     */
    createdAt?: Date;
    /**
     *
     * @type {string}
     * @memberof AuditLogDto
     */
    endpointType?: AuditLogDtoEndpointTypeEnum;
    /**
     *
     * @type {string}
     * @memberof AuditLogDto
     */
    id?: string;
    /**
     *
     * @type {string}
     * @memberof AuditLogDto
     */
    type?: AuditLogDtoTypeEnum;
    /**
     *
     * @type {string}
     * @memberof AuditLogDto
     */
    userEmail?: string;
    /**
     *
     * @type {string}
     * @memberof AuditLogDto
     */
    userId?: string;
    /**
     *
     * @type {string}
     * @memberof AuditLogDto
     */
    userName?: string;
    /**
     *
     * @type {string}
     * @memberof AuditLogDto
     */
    message?: string;
    /**
     *
     * @type {string}
     * @memberof AuditLogDto
     */
    requestData?: string;
}
/**
* @export
* @enum {string}
*/
export declare enum AuditLogDtoEndpointTypeEnum {
    Web = "Web",
    Api = "Api",
    BackgroundTask = "BackgroundTask"
}
/**
* @export
* @enum {string}
*/
export declare enum AuditLogDtoTypeEnum {
    Signin = "Signin",
    Signout = "Signout",
    Signup = "Signup",
    ResentConfirmationEmail = "ResentConfirmationEmail",
    EmailConfirmed = "EmailConfirmed",
    PasswordResetRequested = "PasswordResetRequested",
    PasswordResetSucceeded = "PasswordResetSucceeded",
    PasswordChanged = "PasswordChanged",
    UserAccountUpdated = "UserAccountUpdated",
    UserCreated = "UserCreated",
    UserUpdated = "UserUpdated",
    AccessTokenReset = "AccessTokenReset",
    ScanStarted = "ScanStarted",
    ScanCancelled = "ScanCancelled",
    WebsiteGroupCreated = "WebsiteGroupCreated",
    WebsiteGroupDeleted = "WebsiteGroupDeleted",
    WebsiteGroupUpdated = "WebsiteGroupUpdated",
    WebsiteCreated = "WebsiteCreated",
    WebsiteUpdated = "WebsiteUpdated",
    WebsiteDeleted = "WebsiteDeleted",
    ScheduledScanDeleted = "ScheduledScanDeleted",
    ScheduledScanCreated = "ScheduledScanCreated",
    ScheduledScanUpdated = "ScheduledScanUpdated",
    ScanPolicyCreated = "ScanPolicyCreated",
    ScanPolicyUpdated = "ScanPolicyUpdated",
    ScanPolicyDeleted = "ScanPolicyDeleted",
    CheckedUpdates = "CheckedUpdates",
    ScanDeleted = "ScanDeleted",
    SigninAs = "SigninAs",
    TwoFactorAuthenticationDisabled = "TwoFactorAuthenticationDisabled",
    TwoFactorAuthenticationConfigured = "TwoFactorAuthenticationConfigured",
    TwoFactorAuthenticationRecoveryCodesViewed = "TwoFactorAuthenticationRecoveryCodesViewed",
    TwoFactorAuthenticationEnforcementChanged = "TwoFactorAuthenticationEnforcementChanged",
    SigninWithRecoveryCode = "SigninWithRecoveryCode",
    IssueCreated = "IssueCreated",
    IssueUpdated = "IssueUpdated",
    DeleteUser = "DeleteUser",
    StartVerification = "StartVerification",
    VerifyOwnership = "VerifyOwnership",
    ScanPaused = "ScanPaused",
    ScanResumed = "ScanResumed",
    AccountLicenseUpdated = "AccountLicenseUpdated",
    InvitationLicenseUpdated = "InvitationLicenseUpdated",
    MarkedLateConfirmation = "MarkedLateConfirmation",
    ConfirmSupportAccessRequest = "ConfirmSupportAccessRequest",
    AgentGroupCreated = "AgentGroupCreated",
    AgentGroupUpdated = "AgentGroupUpdated",
    AgentGroupDeleted = "AgentGroupDeleted",
    IpRestrictionAdded = "IpRestrictionAdded",
    IpRestrictionUpdated = "IpRestrictionUpdated",
    IpRestrictionDeleted = "IpRestrictionDeleted",
    IpRestrictionsStatusChanged = "IpRestrictionsStatusChanged",
    RawScanFileRetentionPeriodEnabled = "RawScanFileRetentionPeriodEnabled",
    RawScanFileRetentionPeriodDisabled = "RawScanFileRetentionPeriodDisabled",
    AccountUpdated = "AccountUpdated",
    ScanNotificationRuleCreated = "ScanNotificationRuleCreated",
    ScanNotificationRuleUpdated = "ScanNotificationRuleUpdated",
    ScanNotificationRuleDeleted = "ScanNotificationRuleDeleted",
    ScanNotificationRulePrioritiesUpdated = "ScanNotificationRulePrioritiesUpdated",
    ReportPolicyCreated = "ReportPolicyCreated",
    ReportPolicyUpdated = "ReportPolicyUpdated",
    ReportPolicyDeleted = "ReportPolicyDeleted",
    AgentDeleted = "AgentDeleted",
    DeleteAccount = "DeleteAccount",
    NsScanImported = "NsScanImported",
    AccountsMerged = "AccountsMerged",
    TooManyRequests = "TooManyRequests",
    SupportEditedUser = "SupportEditedUser",
    AgentsAutoUpdateSettingChanged = "AgentsAutoUpdateSettingChanged",
    WebsiteGroupTechContactChanged = "WebsiteGroupTechContactChanged",
    CreateInvitation = "CreateInvitation",
    DeleteInvitation = "DeleteInvitation",
    ScanProfileCreated = "ScanProfileCreated",
    ScanProfileUpdated = "ScanProfileUpdated",
    ScanProfileDeleted = "ScanProfileDeleted",
    GeneralSettingsUpdated = "GeneralSettingsUpdated",
    SecuritySettingsUpdated = "SecuritySettingsUpdated",
    DatabaseSettingsUpdated = "DatabaseSettingsUpdated",
    EmailSettingsUpdated = "EmailSettingsUpdated",
    SmsSettingsUpdated = "SmsSettingsUpdated",
    CloudProviderUpdated = "CloudProviderUpdated",
    SingleSignOnUpdated = "SingleSignOnUpdated",
    IpRestrictionsUpdated = "IpRestrictionsUpdated",
    TechnologyNotificationChanged = "TechnologyNotificationChanged",
    LoginAttemptFailed = "LoginAttemptFailed",
    IpRestrictedSessionsStatusChanged = "IpRestrictedSessionsStatusChanged",
    U2FSecurityKeyConfigured = "U2FSecurityKeyConfigured",
    U2FSecurityKeyReConfigured = "U2FSecurityKeyReConfigured",
    AgentTokenReset = "AgentTokenReset",
    AddOrUpdateTag = "AddOrUpdateTag",
    EncryptionKeysUpdated = "EncryptionKeysUpdated",
    EncryptionKeysDownloaded = "EncryptionKeysDownloaded",
    RoleCreated = "RoleCreated",
    RoleUpdated = "RoleUpdated",
    RoleDelete = "RoleDelete",
    TeamCreated = "TeamCreated",
    TeamUpdated = "TeamUpdated",
    TeamDelete = "TeamDelete",
    DefectDojoReportImported = "DefectDojoReportImported",
    DefectDojoReportImportFailed = "DefectDojoReportImportFailed",
    ScanDataRetentionPeriodEnabled = "ScanDataRetentionPeriodEnabled",
    ScanDataRetentionPeriodDisabled = "ScanDataRetentionPeriodDisabled",
    ScanQueuedAgain = "ScanQueuedAgain",
    ScanFailed = "ScanFailed",
    AgentCommandDelete = "AgentCommandDelete",
    ImportWebsite = "ImportWebsite"
}
/**
 * Check if a given object implements the AuditLogDto interface.
 */
export declare function instanceOfAuditLogDto(value: object): boolean;
export declare function AuditLogDtoFromJSON(json: any): AuditLogDto;
export declare function AuditLogDtoFromJSONTyped(json: any, ignoreDiscriminator: boolean): AuditLogDto;
export declare function AuditLogDtoToJSON(value?: AuditLogDto | null): any;
