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
 */
export declare const AuditLogDtoEndpointTypeEnum: {
    readonly Web: "Web";
    readonly Api: "Api";
    readonly BackgroundTask: "BackgroundTask";
};
export type AuditLogDtoEndpointTypeEnum = typeof AuditLogDtoEndpointTypeEnum[keyof typeof AuditLogDtoEndpointTypeEnum];
/**
 * @export
 */
export declare const AuditLogDtoTypeEnum: {
    readonly Signin: "Signin";
    readonly Signout: "Signout";
    readonly Signup: "Signup";
    readonly ResentConfirmationEmail: "ResentConfirmationEmail";
    readonly EmailConfirmed: "EmailConfirmed";
    readonly PasswordResetRequested: "PasswordResetRequested";
    readonly PasswordResetSucceeded: "PasswordResetSucceeded";
    readonly PasswordChanged: "PasswordChanged";
    readonly UserAccountUpdated: "UserAccountUpdated";
    readonly UserCreated: "UserCreated";
    readonly UserUpdated: "UserUpdated";
    readonly AccessTokenReset: "AccessTokenReset";
    readonly ScanStarted: "ScanStarted";
    readonly ScanCancelled: "ScanCancelled";
    readonly WebsiteGroupCreated: "WebsiteGroupCreated";
    readonly WebsiteGroupDeleted: "WebsiteGroupDeleted";
    readonly WebsiteGroupUpdated: "WebsiteGroupUpdated";
    readonly WebsiteCreated: "WebsiteCreated";
    readonly WebsiteUpdated: "WebsiteUpdated";
    readonly WebsiteDeleted: "WebsiteDeleted";
    readonly ScheduledScanDeleted: "ScheduledScanDeleted";
    readonly ScheduledScanCreated: "ScheduledScanCreated";
    readonly ScheduledScanUpdated: "ScheduledScanUpdated";
    readonly ScanPolicyCreated: "ScanPolicyCreated";
    readonly ScanPolicyUpdated: "ScanPolicyUpdated";
    readonly ScanPolicyDeleted: "ScanPolicyDeleted";
    readonly CheckedUpdates: "CheckedUpdates";
    readonly ScanDeleted: "ScanDeleted";
    readonly SigninAs: "SigninAs";
    readonly TwoFactorAuthenticationDisabled: "TwoFactorAuthenticationDisabled";
    readonly TwoFactorAuthenticationConfigured: "TwoFactorAuthenticationConfigured";
    readonly TwoFactorAuthenticationRecoveryCodesViewed: "TwoFactorAuthenticationRecoveryCodesViewed";
    readonly TwoFactorAuthenticationEnforcementChanged: "TwoFactorAuthenticationEnforcementChanged";
    readonly SigninWithRecoveryCode: "SigninWithRecoveryCode";
    readonly IssueCreated: "IssueCreated";
    readonly IssueUpdated: "IssueUpdated";
    readonly DeleteUser: "DeleteUser";
    readonly StartVerification: "StartVerification";
    readonly VerifyOwnership: "VerifyOwnership";
    readonly ScanPaused: "ScanPaused";
    readonly ScanResumed: "ScanResumed";
    readonly AccountLicenseUpdated: "AccountLicenseUpdated";
    readonly InvitationLicenseUpdated: "InvitationLicenseUpdated";
    readonly MarkedLateConfirmation: "MarkedLateConfirmation";
    readonly ConfirmSupportAccessRequest: "ConfirmSupportAccessRequest";
    readonly AgentGroupCreated: "AgentGroupCreated";
    readonly AgentGroupUpdated: "AgentGroupUpdated";
    readonly AgentGroupDeleted: "AgentGroupDeleted";
    readonly IpRestrictionAdded: "IpRestrictionAdded";
    readonly IpRestrictionUpdated: "IpRestrictionUpdated";
    readonly IpRestrictionDeleted: "IpRestrictionDeleted";
    readonly IpRestrictionsStatusChanged: "IpRestrictionsStatusChanged";
    readonly RawScanFileRetentionPeriodEnabled: "RawScanFileRetentionPeriodEnabled";
    readonly RawScanFileRetentionPeriodDisabled: "RawScanFileRetentionPeriodDisabled";
    readonly AccountUpdated: "AccountUpdated";
    readonly ScanNotificationRuleCreated: "ScanNotificationRuleCreated";
    readonly ScanNotificationRuleUpdated: "ScanNotificationRuleUpdated";
    readonly ScanNotificationRuleDeleted: "ScanNotificationRuleDeleted";
    readonly ScanNotificationRulePrioritiesUpdated: "ScanNotificationRulePrioritiesUpdated";
    readonly ReportPolicyCreated: "ReportPolicyCreated";
    readonly ReportPolicyUpdated: "ReportPolicyUpdated";
    readonly ReportPolicyDeleted: "ReportPolicyDeleted";
    readonly AgentDeleted: "AgentDeleted";
    readonly DeleteAccount: "DeleteAccount";
    readonly NsScanImported: "NsScanImported";
    readonly AccountsMerged: "AccountsMerged";
    readonly TooManyRequests: "TooManyRequests";
    readonly SupportEditedUser: "SupportEditedUser";
    readonly AgentsAutoUpdateSettingChanged: "AgentsAutoUpdateSettingChanged";
    readonly WebsiteGroupTechContactChanged: "WebsiteGroupTechContactChanged";
    readonly CreateInvitation: "CreateInvitation";
    readonly DeleteInvitation: "DeleteInvitation";
    readonly ScanProfileCreated: "ScanProfileCreated";
    readonly ScanProfileUpdated: "ScanProfileUpdated";
    readonly ScanProfileDeleted: "ScanProfileDeleted";
    readonly GeneralSettingsUpdated: "GeneralSettingsUpdated";
    readonly SecuritySettingsUpdated: "SecuritySettingsUpdated";
    readonly DatabaseSettingsUpdated: "DatabaseSettingsUpdated";
    readonly EmailSettingsUpdated: "EmailSettingsUpdated";
    readonly SmsSettingsUpdated: "SmsSettingsUpdated";
    readonly CloudProviderUpdated: "CloudProviderUpdated";
    readonly SingleSignOnUpdated: "SingleSignOnUpdated";
    readonly IpRestrictionsUpdated: "IpRestrictionsUpdated";
    readonly TechnologyNotificationChanged: "TechnologyNotificationChanged";
    readonly LoginAttemptFailed: "LoginAttemptFailed";
    readonly IpRestrictedSessionsStatusChanged: "IpRestrictedSessionsStatusChanged";
    readonly U2FSecurityKeyConfigured: "U2FSecurityKeyConfigured";
    readonly U2FSecurityKeyReConfigured: "U2FSecurityKeyReConfigured";
    readonly AgentTokenReset: "AgentTokenReset";
    readonly AddOrUpdateTag: "AddOrUpdateTag";
    readonly EncryptionKeysUpdated: "EncryptionKeysUpdated";
    readonly EncryptionKeysDownloaded: "EncryptionKeysDownloaded";
    readonly RoleCreated: "RoleCreated";
    readonly RoleUpdated: "RoleUpdated";
    readonly RoleDelete: "RoleDelete";
    readonly TeamCreated: "TeamCreated";
    readonly TeamUpdated: "TeamUpdated";
    readonly TeamDelete: "TeamDelete";
    readonly DefectDojoReportImported: "DefectDojoReportImported";
    readonly DefectDojoReportImportFailed: "DefectDojoReportImportFailed";
    readonly ScanDataRetentionPeriodEnabled: "ScanDataRetentionPeriodEnabled";
    readonly ScanDataRetentionPeriodDisabled: "ScanDataRetentionPeriodDisabled";
    readonly ScanQueuedAgain: "ScanQueuedAgain";
    readonly ScanFailed: "ScanFailed";
    readonly AgentCommandDelete: "AgentCommandDelete";
    readonly ImportWebsite: "ImportWebsite";
    readonly LimitingRole: "LimitingRole";
};
export type AuditLogDtoTypeEnum = typeof AuditLogDtoTypeEnum[keyof typeof AuditLogDtoTypeEnum];
/**
 * Check if a given object implements the AuditLogDto interface.
 */
export declare function instanceOfAuditLogDto(value: object): boolean;
export declare function AuditLogDtoFromJSON(json: any): AuditLogDto;
export declare function AuditLogDtoFromJSONTyped(json: any, ignoreDiscriminator: boolean): AuditLogDto;
export declare function AuditLogDtoToJSON(value?: AuditLogDto | null): any;
