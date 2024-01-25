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
import type { AdditionalWebsiteModel } from './AdditionalWebsiteModel';
import type { ApiFileModel } from './ApiFileModel';
import type { BasicAuthenticationSettingModel } from './BasicAuthenticationSettingModel';
import type { BusinessLogicRecorderSettingModel } from './BusinessLogicRecorderSettingModel';
import type { ClientCertificateAuthenticationApiModel } from './ClientCertificateAuthenticationApiModel';
import type { ExcludedLinkModel } from './ExcludedLinkModel';
import type { ExcludedUsageTrackerModel } from './ExcludedUsageTrackerModel';
import type { FormAuthenticationSettingModel } from './FormAuthenticationSettingModel';
import type { HeaderAuthenticationModel } from './HeaderAuthenticationModel';
import type { OAuth2SettingApiModel } from './OAuth2SettingApiModel';
import type { PreRequestScriptSettingModel } from './PreRequestScriptSettingModel';
import type { ScanTimeWindowModel } from './ScanTimeWindowModel';
import type { ScheduledScanRecurrenceApiModel } from './ScheduledScanRecurrenceApiModel';
import type { SharkModel } from './SharkModel';
import type { UrlRewriteExcludedPathModel } from './UrlRewriteExcludedPathModel';
import type { UrlRewriteRuleModel } from './UrlRewriteRuleModel';
/**
 * Contains properties that required to update scheduled scan.
 * @export
 * @interface UpdateScheduledScanApiModel
 */
export interface UpdateScheduledScanApiModel {
    /**
     * Gets or sets a value indicating whether scheduled scan is disabled.
     * @type {boolean}
     * @memberof UpdateScheduledScanApiModel
     */
    disabled?: boolean;
    /**
     * Gets or sets the scan identifier.
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    id: string;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    name: string;
    /**
     * Gets or sets the next execution time.
     * Date string must be in the same format as in the account settings.
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    nextExecutionTime: string;
    /**
     * Gets or sets the run interval of scheduled scan.
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    scheduleRunType: UpdateScheduledScanApiModelScheduleRunTypeEnum;
    /**
     *
     * @type {ScheduledScanRecurrenceApiModel}
     * @memberof UpdateScheduledScanApiModel
     */
    customRecurrence?: ScheduledScanRecurrenceApiModel;
    /**
     * Gets or sets the target URI.
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    targetUri?: string;
    /**
     * Gets or sets whether is target URL required.
     * @type {boolean}
     * @memberof UpdateScheduledScanApiModel
     */
    readonly isTargetUrlRequired?: boolean;
    /**
     * Gets or sets the type of the create.
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    createType?: UpdateScheduledScanApiModelCreateTypeEnum;
    /**
     * Gets or sets the website group identifier. This property is required if CreateType is WebsiteGroup
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    websiteGroupId?: string;
    /**
     * Gets or sets the additional websites to scan.
     * @type {Array<AdditionalWebsiteModel>}
     * @memberof UpdateScheduledScanApiModel
     */
    additionalWebsites?: Array<AdditionalWebsiteModel>;
    /**
     *
     * @type {BasicAuthenticationSettingModel}
     * @memberof UpdateScheduledScanApiModel
     */
    basicAuthenticationApiModel?: BasicAuthenticationSettingModel;
    /**
     *
     * @type {ClientCertificateAuthenticationApiModel}
     * @memberof UpdateScheduledScanApiModel
     */
    clientCertificateAuthenticationSetting?: ClientCertificateAuthenticationApiModel;
    /**
     * Gets or sets the cookies. Separate multiple cookies with semicolon. Cookie values must be URL encoded. You can use the
     * following format: Cookiename=Value
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    cookies?: string;
    /**
     * Gets or sets a value indicating whether parallel attacker is enabled.
     * Default: true
     * @type {boolean}
     * @memberof UpdateScheduledScanApiModel
     */
    crawlAndAttack?: boolean;
    /**
     * Gets or sets a value indicating whether Heuristic URL Rewrite support is enabled together with custom URL Rewrite
     * support.
     * @type {boolean}
     * @memberof UpdateScheduledScanApiModel
     */
    enableHeuristicChecksInCustomUrlRewrite?: boolean;
    /**
     * Gets or sets the excluded links.
     * Default: "(log|sign)\\-?(out|off)", "exit", "endsession", "gtm\\.js"
     * @type {Array<ExcludedLinkModel>}
     * @memberof UpdateScheduledScanApiModel
     */
    excludedLinks?: Array<ExcludedLinkModel>;
    /**
     * Gets or sets the excluded usage trackers.
     * @type {Array<ExcludedUsageTrackerModel>}
     * @memberof UpdateScheduledScanApiModel
     */
    excludedUsageTrackers?: Array<ExcludedUsageTrackerModel>;
    /**
     * Gets or sets the disallowed http methods.
     * @type {Array<string>}
     * @memberof UpdateScheduledScanApiModel
     */
    disallowedHttpMethods?: Array<UpdateScheduledScanApiModelDisallowedHttpMethodsEnum>;
    /**
     * Gets or sets a value indicating whether links should be excluded/included.
     * Default: <see ref="bool.True" />
     * @type {boolean}
     * @memberof UpdateScheduledScanApiModel
     */
    excludeLinks?: boolean;
    /**
     * Specifies whether the authentication related pages like login, logout etc. should be excluded from the scan.
     * If form authentication is enabled, exclude authentication pages will be set as true. If you want to scan exclude authentication pages please set as false.
     * @type {boolean}
     * @memberof UpdateScheduledScanApiModel
     */
    excludeAuthenticationPages?: boolean;
    /**
     * Gets or sets a value indicating whether automatic crawling is enabled.
     * @type {boolean}
     * @memberof UpdateScheduledScanApiModel
     */
    findAndFollowNewLinks?: boolean;
    /**
     *
     * @type {FormAuthenticationSettingModel}
     * @memberof UpdateScheduledScanApiModel
     */
    formAuthenticationSettingModel?: FormAuthenticationSettingModel;
    /**
     *
     * @type {HeaderAuthenticationModel}
     * @memberof UpdateScheduledScanApiModel
     */
    headerAuthentication?: HeaderAuthenticationModel;
    /**
     *
     * @type {SharkModel}
     * @memberof UpdateScheduledScanApiModel
     */
    sharkSetting?: SharkModel;
    /**
     * Gets or sets the type of the authentication profile option.
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    authenticationProfileOption?: UpdateScheduledScanApiModelAuthenticationProfileOptionEnum;
    /**
     * Gets or sets the type of the authentication profile identifier.
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    authenticationProfileId?: string;
    /**
     * Gets or sets the imported links.
     * @type {Array<string>}
     * @memberof UpdateScheduledScanApiModel
     */
    importedLinks?: Array<string>;
    /**
     * Gets or sets the imported files. If imported files have not contains any URL, the file not added to scan profile.
     * @type {Array<ApiFileModel>}
     * @memberof UpdateScheduledScanApiModel
     */
    importedFiles?: Array<ApiFileModel>;
    /**
     * Gets or sets a value indicating whether max scan duration is enabled.
     * This is only used for scheduled group scan and regular group scan.
     * @type {boolean}
     * @memberof UpdateScheduledScanApiModel
     */
    isMaxScanDurationEnabled?: boolean;
    /**
     * Gets or sets the root path maximum dynamic signatures for heuristic URL Rewrite detection.
     * Default: 60
     * @type {number}
     * @memberof UpdateScheduledScanApiModel
     */
    maxDynamicSignatures?: number;
    /**
     * Gets or sets the maximum duration of the scan in hours.
     * Default: 48 hours
     * @type {number}
     * @memberof UpdateScheduledScanApiModel
     */
    maxScanDuration?: number;
    /**
     * Gets or sets the scan policy identifier.
     * Default: Default Security Checks
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    policyId?: string;
    /**
     * Gets or sets the report policy identifier.
     * Default: Default Report Policy
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    reportPolicyId?: string;
    /**
     * Gets or sets the scan scope.
     * Default: {Invicti.Cloud.Core.Models.ScanTaskScope.EnteredPathAndBelow}
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    scope?: UpdateScheduledScanApiModelScopeEnum;
    /**
     * Gets or sets the sub path maximum dynamic signatures for heuristic URL Rewrite detection.
     * Default: 30
     * @type {number}
     * @memberof UpdateScheduledScanApiModel
     */
    subPathMaxDynamicSignatures?: number;
    /**
     *
     * @type {ScanTimeWindowModel}
     * @memberof UpdateScheduledScanApiModel
     */
    timeWindow?: ScanTimeWindowModel;
    /**
     * Gets or sets the extensions that will be analyzed for heuristic URL Rewrite detection.
     * Default: htm,html
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    urlRewriteAnalyzableExtensions?: string;
    /**
     * Gets or sets the block separators for heuristic URL Rewrite detection.
     * Default: /_ $.,;|:
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    urlRewriteBlockSeparators?: string;
    /**
     * Gets or sets the URL Rewrite mode.
     * Default: Heuristic
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    urlRewriteMode?: UpdateScheduledScanApiModelUrlRewriteModeEnum;
    /**
     * Gets or sets the URL Rewrite rules.
     * @type {Array<UrlRewriteRuleModel>}
     * @memberof UpdateScheduledScanApiModel
     */
    urlRewriteRules?: Array<UrlRewriteRuleModel>;
    /**
     *
     * @type {PreRequestScriptSettingModel}
     * @memberof UpdateScheduledScanApiModel
     */
    preRequestScriptSetting?: PreRequestScriptSettingModel;
    /**
     * Gets or sets a value indicating whether http and https protocols are differentiated.
     * @type {boolean}
     * @memberof UpdateScheduledScanApiModel
     */
    doNotDifferentiateProtocols?: boolean;
    /**
     * Gets or sets the URL rewrite excluded links.
     * @type {Array<UrlRewriteExcludedPathModel>}
     * @memberof UpdateScheduledScanApiModel
     */
    urlRewriteExcludedLinks?: Array<UrlRewriteExcludedPathModel>;
    /**
     *
     * @type {OAuth2SettingApiModel}
     * @memberof UpdateScheduledScanApiModel
     */
    oAuth2SettingModel?: OAuth2SettingApiModel;
    /**
     * Defines whether a pci scan task going to be started.
     * @type {boolean}
     * @memberof UpdateScheduledScanApiModel
     */
    enablePciScanTask?: boolean;
    /**
     *
     * @type {BusinessLogicRecorderSettingModel}
     * @memberof UpdateScheduledScanApiModel
     */
    businessLogicRecorderSetting?: BusinessLogicRecorderSettingModel;
    /**
     * Gets or sets the tags
     * @type {Array<string>}
     * @memberof UpdateScheduledScanApiModel
     */
    tags?: Array<string>;
    /**
     * Gets or sets the Comments
     * @type {string}
     * @memberof UpdateScheduledScanApiModel
     */
    comments?: string;
}
/**
 * @export
 */
export declare const UpdateScheduledScanApiModelScheduleRunTypeEnum: {
    readonly Once: "Once";
    readonly Daily: "Daily";
    readonly Weekly: "Weekly";
    readonly Monthly: "Monthly";
    readonly Quarterly: "Quarterly";
    readonly Biannually: "Biannually";
    readonly Yearly: "Yearly";
    readonly Custom: "Custom";
};
export type UpdateScheduledScanApiModelScheduleRunTypeEnum = typeof UpdateScheduledScanApiModelScheduleRunTypeEnum[keyof typeof UpdateScheduledScanApiModelScheduleRunTypeEnum];
/**
 * @export
 */
export declare const UpdateScheduledScanApiModelCreateTypeEnum: {
    readonly Website: "Website";
    readonly WebsiteGroup: "WebsiteGroup";
};
export type UpdateScheduledScanApiModelCreateTypeEnum = typeof UpdateScheduledScanApiModelCreateTypeEnum[keyof typeof UpdateScheduledScanApiModelCreateTypeEnum];
/**
 * @export
 */
export declare const UpdateScheduledScanApiModelDisallowedHttpMethodsEnum: {
    readonly Get: "GET";
    readonly Post: "POST";
    readonly Connect: "CONNECT";
    readonly Head: "HEAD";
    readonly Trace: "TRACE";
    readonly Debug: "DEBUG";
    readonly Track: "TRACK";
    readonly Put: "PUT";
    readonly Options: "OPTIONS";
    readonly Delete: "DELETE";
    readonly Link: "LINK";
    readonly Unlink: "UNLINK";
    readonly Patch: "PATCH";
};
export type UpdateScheduledScanApiModelDisallowedHttpMethodsEnum = typeof UpdateScheduledScanApiModelDisallowedHttpMethodsEnum[keyof typeof UpdateScheduledScanApiModelDisallowedHttpMethodsEnum];
/**
 * @export
 */
export declare const UpdateScheduledScanApiModelAuthenticationProfileOptionEnum: {
    readonly DontUse: "DontUse";
    readonly UseMatchedProfile: "UseMatchedProfile";
    readonly SelectedProfile: "SelectedProfile";
};
export type UpdateScheduledScanApiModelAuthenticationProfileOptionEnum = typeof UpdateScheduledScanApiModelAuthenticationProfileOptionEnum[keyof typeof UpdateScheduledScanApiModelAuthenticationProfileOptionEnum];
/**
 * @export
 */
export declare const UpdateScheduledScanApiModelScopeEnum: {
    readonly EnteredPathAndBelow: "EnteredPathAndBelow";
    readonly OnlyEnteredUrl: "OnlyEnteredUrl";
    readonly WholeDomain: "WholeDomain";
};
export type UpdateScheduledScanApiModelScopeEnum = typeof UpdateScheduledScanApiModelScopeEnum[keyof typeof UpdateScheduledScanApiModelScopeEnum];
/**
 * @export
 */
export declare const UpdateScheduledScanApiModelUrlRewriteModeEnum: {
    readonly None: "None";
    readonly Heuristic: "Heuristic";
    readonly Custom: "Custom";
};
export type UpdateScheduledScanApiModelUrlRewriteModeEnum = typeof UpdateScheduledScanApiModelUrlRewriteModeEnum[keyof typeof UpdateScheduledScanApiModelUrlRewriteModeEnum];
/**
 * Check if a given object implements the UpdateScheduledScanApiModel interface.
 */
export declare function instanceOfUpdateScheduledScanApiModel(value: object): boolean;
export declare function UpdateScheduledScanApiModelFromJSON(json: any): UpdateScheduledScanApiModel;
export declare function UpdateScheduledScanApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateScheduledScanApiModel;
export declare function UpdateScheduledScanApiModelToJSON(value?: UpdateScheduledScanApiModel | null): any;
