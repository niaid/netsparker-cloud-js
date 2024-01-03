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

import { exists, mapValues } from '../runtime';
import type { AdditionalWebsiteModel } from './AdditionalWebsiteModel';
import {
    AdditionalWebsiteModelFromJSON,
    AdditionalWebsiteModelFromJSONTyped,
    AdditionalWebsiteModelToJSON,
} from './AdditionalWebsiteModel';
import type { BusinessLogicRecorderSettingModel } from './BusinessLogicRecorderSettingModel';
import {
    BusinessLogicRecorderSettingModelFromJSON,
    BusinessLogicRecorderSettingModelFromJSONTyped,
    BusinessLogicRecorderSettingModelToJSON,
} from './BusinessLogicRecorderSettingModel';
import type { PciScanTaskViewModel } from './PciScanTaskViewModel';
import {
    PciScanTaskViewModelFromJSON,
    PciScanTaskViewModelFromJSONTyped,
    PciScanTaskViewModelToJSON,
} from './PciScanTaskViewModel';
import type { ReducedScanTaskProfile } from './ReducedScanTaskProfile';
import {
    ReducedScanTaskProfileFromJSON,
    ReducedScanTaskProfileFromJSONTyped,
    ReducedScanTaskProfileToJSON,
} from './ReducedScanTaskProfile';
import type { ScanTimeWindowModel } from './ScanTimeWindowModel';
import {
    ScanTimeWindowModelFromJSON,
    ScanTimeWindowModelFromJSONTyped,
    ScanTimeWindowModelToJSON,
} from './ScanTimeWindowModel';
import type { UrlRewriteExcludedPathModel } from './UrlRewriteExcludedPathModel';
import {
    UrlRewriteExcludedPathModelFromJSON,
    UrlRewriteExcludedPathModelFromJSONTyped,
    UrlRewriteExcludedPathModelToJSON,
} from './UrlRewriteExcludedPathModel';
import type { UrlRewriteRuleModel } from './UrlRewriteRuleModel';
import {
    UrlRewriteRuleModelFromJSON,
    UrlRewriteRuleModelFromJSONTyped,
    UrlRewriteRuleModelToJSON,
} from './UrlRewriteRuleModel';
import type { VcsCommitInfo } from './VcsCommitInfo';
import {
    VcsCommitInfoFromJSON,
    VcsCommitInfoFromJSONTyped,
    VcsCommitInfoToJSON,
} from './VcsCommitInfo';

/**
 * Represents a model for carrying {Invicti.Cloud.Core.Models.ScanTask} content.
 * @export
 * @interface ScanTaskModel
 */
export interface ScanTaskModel {
    /**
     * Gets or sets the additional websites to scan.
     * @type {Array<AdditionalWebsiteModel>}
     * @memberof ScanTaskModel
     */
    additionalWebsites?: Array<AdditionalWebsiteModel>;
    /**
     * Gets or sets the agent id.
     * @type {string}
     * @memberof ScanTaskModel
     */
    agentId?: string;
    /**
     * Gets or sets the agent name.
     * @type {string}
     * @memberof ScanTaskModel
     */
    agentName?: string;
    /**
     * Gets or sets the cookies.
     * @type {string}
     * @memberof ScanTaskModel
     */
    cookies?: string;
    /**
     * Gets or sets a value indicating whether parallel attacker is enabled.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    crawlAndAttack?: boolean;
    /**
     * Gets or sets deleted date.
     * @type {Date}
     * @memberof ScanTaskModel
     */
    deletedOn?: Date;
    /**
     * Gets or sets a value indicating whether Heuristic URL Rewrite support is enabled together with custom URL Rewrite
     * support.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    enableHeuristicChecksInCustomUrlRewrite?: boolean;
    /**
     * Gets or sets the excluded links.
     * @type {string}
     * @memberof ScanTaskModel
     */
    excludedLinks?: string;
    /**
     * Gets or sets a value indicating whether links should be excluded/included.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    excludeLinks?: boolean;
    /**
     * Gets or sets the disallowed HTTP methods.
     * @type {string}
     * @memberof ScanTaskModel
     */
    disallowedHttpMethods?: string;
    /**
     * Gets or sets a value indicating whether automatic crawling is enabled.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    findAndFollowNewLinks?: boolean;
    /**
     * Gets or sets the imported links.
     * @type {string}
     * @memberof ScanTaskModel
     */
    importedLinks?: string;
    /**
     * Gets or sets the all imported links which might be added via manually or via importing a file.
     * This property is used for status/reports pages.
     * @type {string}
     * @memberof ScanTaskModel
     */
    allImportedLinks?: string;
    /**
     * Gets the desktop scan identifier.
     * @type {string}
     * @memberof ScanTaskModel
     */
    desktopScanId?: string;
    /**
     * Gets or sets initiated date in user's preferred format.
     * @type {string}
     * @memberof ScanTaskModel
     */
    initiatedTime?: string;
    /**
     * Gets or sets the initiated date in user's preferred format.
     * @type {string}
     * @memberof ScanTaskModel
     */
    initiatedDate?: string;
    /**
     * Gets or sets the initiated date.
     * @type {Date}
     * @memberof ScanTaskModel
     */
    initiatedAt?: Date;
    /**
     * Gets or sets the root path maximum dynamic signatures for heuristic URL Rewrite detection.
     * @type {number}
     * @memberof ScanTaskModel
     */
    maxDynamicSignatures?: number;
    /**
     * Gets or sets the maximum duration of the scan in hours.
     * @type {number}
     * @memberof ScanTaskModel
     */
    maxScanDuration?: number;
    /**
     * Gets or sets the duration
     * @type {string}
     * @memberof ScanTaskModel
     */
    duration?: string;
    /**
     * Gets or sets the description of the policy.
     * @type {string}
     * @memberof ScanTaskModel
     */
    policyDescription?: string;
    /**
     * Gets or sets the foreign key reference to the related Policy instance.
     * @type {string}
     * @memberof ScanTaskModel
     */
    policyId?: string;
    /**
     * Gets or sets the foreign key reference to the related Policy User instance.
     * @type {string}
     * @memberof ScanTaskModel
     */
    policyUserId?: string;
    /**
     * Gets or sets the foreign key reference to the related Policy IsDefault instance.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    policyIsDefault?: boolean;
    /**
     * Gets or sets the foreign key reference to the related Policy IsShared instance.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    policyIsShared?: boolean;
    /**
     * Gets or sets the name of the policy.
     * @type {string}
     * @memberof ScanTaskModel
     */
    policyName?: string;
    /**
     * Gets or sets the foreign key reference to the related Authentication Profile instance.
     * @type {string}
     * @memberof ScanTaskModel
     */
    authenticationProfileId?: string;
    /**
     * Gets or sets the the authentication profile option.
     * @type {string}
     * @memberof ScanTaskModel
     */
    authenticationProfileOption?: ScanTaskModelAuthenticationProfileOptionEnum;
    /**
     * Gets or sets the description of the report policy.
     * @type {string}
     * @memberof ScanTaskModel
     */
    reportPolicyDescription?: string;
    /**
     * Gets or sets the foreign key reference to the related {Invicti.Cloud.Core.Models.ReportPolicySetting} instance.
     * @type {string}
     * @memberof ScanTaskModel
     */
    reportPolicyId?: string;
    /**
     * Gets or sets the foreign key reference to the related {Invicti.Cloud.Core.Models.ReportPolicySetting} User instance.
     * @type {string}
     * @memberof ScanTaskModel
     */
    reportPolicyUserId?: string;
    /**
     * Gets or sets the foreign key reference to the related {Invicti.Cloud.Core.Models.ReportPolicySetting} IsDefault instance.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    reportPolicyIsDefault?: boolean;
    /**
     * Gets or sets the foreign key reference to the related {Invicti.Cloud.Core.Models.ReportPolicySetting} IsDefault instance.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    reportPolicyIsShared?: boolean;
    /**
     * Gets or sets the name of the report policy.
     * @type {string}
     * @memberof ScanTaskModel
     */
    reportPolicyName?: string;
    /**
     * Gets or sets the scan scope.
     * @type {string}
     * @memberof ScanTaskModel
     */
    scope?: ScanTaskModelScopeEnum;
    /**
     * Gets or sets the sub path maximum dynamic signatures for heuristic URL Rewrite detection.
     * @type {number}
     * @memberof ScanTaskModel
     */
    subPathMaxDynamicSignatures?: number;
    /**
     * Gets or sets target path.
     * @type {string}
     * @memberof ScanTaskModel
     */
    targetPath?: string;
    /**
     * Gets or sets TargetUrl.
     * @type {string}
     * @memberof ScanTaskModel
     */
    targetUrl?: string;
    /**
     * Gets or sets the target URL root.
     * @type {string}
     * @memberof ScanTaskModel
     */
    targetUrlRoot?: string;
    /**
     * 
     * @type {ScanTimeWindowModel}
     * @memberof ScanTaskModel
     */
    timeWindow?: ScanTimeWindowModel;
    /**
     * Gets or sets the total vulnerability count without information vulnerabilities.
     * @type {number}
     * @memberof ScanTaskModel
     */
    totalVulnerabilityCount?: number;
    /**
     * Gets or sets the extensions that will be analyzed for heuristic URL Rewrite detection.
     * @type {string}
     * @memberof ScanTaskModel
     */
    urlRewriteAnalyzableExtensions?: string;
    /**
     * Gets or sets the block separators for heuristic URL Rewrite detection.
     * @type {string}
     * @memberof ScanTaskModel
     */
    urlRewriteBlockSeparators?: string;
    /**
     * Gets or sets the URL Rewrite mode.
     * @type {string}
     * @memberof ScanTaskModel
     */
    urlRewriteMode?: ScanTaskModelUrlRewriteModeEnum;
    /**
     * Gets or sets the URL Rewrite rules.
     * @type {Array<UrlRewriteRuleModel>}
     * @memberof ScanTaskModel
     */
    urlRewriteRules?: Array<UrlRewriteRuleModel>;
    /**
     * Gets or sets the URL rewrite excluded links.
     * @type {Array<UrlRewriteExcludedPathModel>}
     * @memberof ScanTaskModel
     */
    urlRewriteExcludedLinks?: Array<UrlRewriteExcludedPathModel>;
    /**
     * Gets or sets the user identifier.
     * @type {string}
     * @memberof ScanTaskModel
     */
    userId?: string;
    /**
     * 
     * @type {VcsCommitInfo}
     * @memberof ScanTaskModel
     */
    vcsCommitInfo?: VcsCommitInfo;
    /**
     * Gets or sets the name of the website.
     * @type {string}
     * @memberof ScanTaskModel
     */
    websiteName?: string;
    /**
     * Gets or sets the website URL.
     * @type {string}
     * @memberof ScanTaskModel
     */
    websiteUrl?: string;
    /**
     * Gets or sets the description of the website.
     * @type {string}
     * @memberof ScanTaskModel
     */
    websiteDescription?: string;
    /**
     * Gets or sets the description of the website protocol.
     * @type {string}
     * @memberof ScanTaskModel
     */
    websiteProtocol?: ScanTaskModelWebsiteProtocolEnum;
    /**
     * Determines whether if the website is deleted.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    websiteIsDeleted?: boolean;
    /**
     * gets or sets is latest completed full scan task of website
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    isWebsiteLatestCompletedFullScanTask?: boolean;
    /**
     * Gets or sets the pci scan task is enabled.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    enablePciScanTask?: boolean;
    /**
     * 
     * @type {PciScanTaskViewModel}
     * @memberof ScanTaskModel
     */
    pciScanTask?: PciScanTaskViewModel;
    /**
     * Gets or sets the user's name.
     * @type {string}
     * @memberof ScanTaskModel
     */
    userName?: string;
    /**
     * Determines whether if the scan task model has initiated queued scan.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    queuedScanTaskExist?: boolean;
    /**
     * Gets or sets the scan task profile id
     * @type {string}
     * @memberof ScanTaskModel
     */
    scanTaskProfileId?: string;
    /**
     * 
     * @type {ReducedScanTaskProfile}
     * @memberof ScanTaskModel
     */
    scanTaskProfile?: ReducedScanTaskProfile;
    /**
     * The group ids of website in it
     * @type {Array<string>}
     * @memberof ScanTaskModel
     */
    websiteGroupIds?: Array<string>;
    /**
     * Gets or sets the scan task launch setting comments
     * @type {string}
     * @memberof ScanTaskModel
     */
    comments?: string;
    /**
     * 
     * @type {BusinessLogicRecorderSettingModel}
     * @memberof ScanTaskModel
     */
    businessLogicRecorderSetting?: BusinessLogicRecorderSettingModel;
    /**
     * Gets or sets the scan task launch setting comments
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    scanProfileChanged?: boolean;
    /**
     * Gets or sets the number of steps (HTTP requests) completed thus far.
     * @type {number}
     * @memberof ScanTaskModel
     */
    completedSteps?: number;
    /**
     * Gets or sets the estimated launch time in minutes for queued scans.
     * @type {number}
     * @memberof ScanTaskModel
     */
    estimatedLaunchTime?: number;
    /**
     * Gets or sets the estimated total number of steps (HTTP requests) that this scan will undertake.
     * @type {number}
     * @memberof ScanTaskModel
     */
    estimatedSteps?: number;
    /**
     * Gets or sets FailureReason
     * @type {string}
     * @memberof ScanTaskModel
     */
    failureReason?: ScanTaskModelFailureReasonEnum;
    /**
     * Gets the failure reason description.
     * @type {string}
     * @memberof ScanTaskModel
     */
    failureReasonDescription?: string;
    /**
     * Gets the failure reason string.
     * @type {string}
     * @memberof ScanTaskModel
     */
    readonly failureReasonString?: string;
    /**
     * Gets or sets the global threat level.
     * @type {string}
     * @memberof ScanTaskModel
     */
    globalThreatLevel?: ScanTaskModelGlobalThreatLevelEnum;
    /**
     * Gets the global vulnerability critical count.
     * @type {number}
     * @memberof ScanTaskModel
     */
    globalVulnerabilityCriticalCount?: number;
    /**
     * Gets the global vulnerability high count.
     * @type {number}
     * @memberof ScanTaskModel
     */
    globalVulnerabilityHighCount?: number;
    /**
     * Gets the global vulnerability information count.
     * @type {number}
     * @memberof ScanTaskModel
     */
    globalVulnerabilityInfoCount?: number;
    /**
     * Gets the global vulnerability information count.
     * @type {number}
     * @memberof ScanTaskModel
     */
    globalVulnerabilityBestPracticeCount?: number;
    /**
     * Gets the global vulnerability low count.
     * @type {number}
     * @memberof ScanTaskModel
     */
    globalVulnerabilityLowCount?: number;
    /**
     * Gets the global vulnerability medium count.
     * @type {number}
     * @memberof ScanTaskModel
     */
    globalVulnerabilityMediumCount?: number;
    /**
     * Gets or sets Id.
     * @type {string}
     * @memberof ScanTaskModel
     */
    id?: string;
    /**
     * Gets a value indicating whether scan is completed  with any state.
     * @type {boolean}
     * @memberof ScanTaskModel
     */
    readonly isCompleted?: boolean;
    /**
     * Gets the completed percentage.
     * @type {number}
     * @memberof ScanTaskModel
     */
    readonly percentage?: number;
    /**
     * Gets or sets the Phase.
     * @type {string}
     * @memberof ScanTaskModel
     */
    phase?: ScanTaskModelPhaseEnum;
    /**
     * Gets or sets the scan group identifier.
     * @type {string}
     * @memberof ScanTaskModel
     */
    scanTaskGroupId?: string;
    /**
     * Gets or sets the type of the scan.
     * @type {string}
     * @memberof ScanTaskModel
     */
    scanType?: ScanTaskModelScanTypeEnum;
    /**
     * Gets or sets the scheduled scan identifier.
     * @type {string}
     * @memberof ScanTaskModel
     */
    scheduledScanId?: string;
    /**
     * Gets or sets State.
     * @type {string}
     * @memberof ScanTaskModel
     */
    state?: ScanTaskModelStateEnum;
    /**
     * Gets or sets the date and time at which this task state was last changed.
     * @type {Date}
     * @memberof ScanTaskModel
     */
    stateChanged?: Date;
    /**
     * Gets or sets the threat level.
     * @type {string}
     * @memberof ScanTaskModel
     */
    threatLevel?: ScanTaskModelThreatLevelEnum;
    /**
     * Gets or sets the count of vulnerabilities with critical level severity.
     * @type {number}
     * @memberof ScanTaskModel
     */
    vulnerabilityCriticalCount?: number;
    /**
     * Gets or sets the count of vulnerabilities with high level severity.
     * @type {number}
     * @memberof ScanTaskModel
     */
    vulnerabilityHighCount?: number;
    /**
     * Gets or sets the count of vulnerabilities with information level severity.
     * @type {number}
     * @memberof ScanTaskModel
     */
    vulnerabilityInfoCount?: number;
    /**
     * Gets or sets the count of vulnerabilities with best practice level severity.
     * @type {number}
     * @memberof ScanTaskModel
     */
    vulnerabilityBestPracticeCount?: number;
    /**
     * Gets or sets the count of vulnerabilities with low level severity.
     * @type {number}
     * @memberof ScanTaskModel
     */
    vulnerabilityLowCount?: number;
    /**
     * Gets or sets the count of vulnerabilities with medium level severity.
     * @type {number}
     * @memberof ScanTaskModel
     */
    vulnerabilityMediumCount?: number;
    /**
     * Gets the website identifier.
     * @type {string}
     * @memberof ScanTaskModel
     */
    websiteId?: string;
    /**
     * Date and time at which this task was initiated.
     * @type {Date}
     * @memberof ScanTaskModel
     */
    initiated?: Date;
    /**
     * 
     * @type {Array<string>}
     * @memberof ScanTaskModel
     */
    tags?: Array<string>;
}

/**
* @export
* @enum {string}
*/
export enum ScanTaskModelAuthenticationProfileOptionEnum {
    DontUse = 'DontUse',
    UseMatchedProfile = 'UseMatchedProfile',
    SelectedProfile = 'SelectedProfile'
}
/**
* @export
* @enum {string}
*/
export enum ScanTaskModelScopeEnum {
    EnteredPathAndBelow = 'EnteredPathAndBelow',
    OnlyEnteredUrl = 'OnlyEnteredUrl',
    WholeDomain = 'WholeDomain'
}
/**
* @export
* @enum {string}
*/
export enum ScanTaskModelUrlRewriteModeEnum {
    None = 'None',
    Heuristic = 'Heuristic',
    Custom = 'Custom'
}
/**
* @export
* @enum {string}
*/
export enum ScanTaskModelWebsiteProtocolEnum {
    Http = 'Http',
    Https = 'Https'
}
/**
* @export
* @enum {string}
*/
export enum ScanTaskModelFailureReasonEnum {
    None = 'None',
    Request = 'Request',
    HeadRequest = 'HeadRequest',
    RedirectDetected = 'RedirectDetected',
    TimeoutDetected = 'TimeoutDetected',
    MaxLogoutExceeded = 'MaxLogoutExceeded',
    RequestFailed = 'RequestFailed',
    Response = 'Response',
    CrawlerRequest = 'CrawlerRequest',
    AttackerRequest = 'AttackerRequest',
    ReCrawlerRequest = 'ReCrawlerRequest',
    Finished = 'Finished',
    LinkNotFound = 'LinkNotFound',
    RecalculateAttackPossibilities = 'RecalculateAttackPossibilities',
    PhaseCrawlStarted = 'PhaseCrawlStarted',
    PhaseAttackStarted = 'PhaseAttackStarted',
    PhaseReCrawlStarted = 'PhaseReCrawlStarted',
    CrawlerPossibility = 'CrawlerPossibility',
    ReCrawlerPossibilities = 'ReCrawlerPossibilities',
    HostUnavailable = 'HostUnavailable',
    NameResolutionFailure = 'NameResolutionFailure',
    ProxyFailure = 'ProxyFailure',
    OutOfDiskSpace = 'OutOfDiskSpace',
    ProxyAuthenticationRequired = 'ProxyAuthenticationRequired',
    OAuth2EndpointError = 'OAuth2EndpointError',
    TargetLinkTimeoutDetected = 'TargetLinkTimeoutDetected',
    LoginFailed = 'LoginFailed',
    ScanTargetNotReachable = 'ScanTargetNotReachable',
    ScanPolicyNotFound = 'ScanPolicyNotFound',
    ReportPolicyNotFound = 'ReportPolicyNotFound',
    SecurityProtocolTypeNotSupported = 'SecurityProtocolTypeNotSupported',
    UnableToLoadScanSession = 'UnableToLoadScanSession',
    AgentNotAvailable = 'AgentNotAvailable',
    ScanNotAllowed = 'ScanNotAllowed',
    UnableToFindAutoSaveNdb = 'UnableToFindAutoSaveNdb',
    ErrorOccurredOnScanFailed = 'ErrorOccurredOnScanFailed',
    ErrorOccurredOnPause = 'ErrorOccurredOnPause',
    ErrorOccurredOnCancel = 'ErrorOccurredOnCancel',
    ErrorOccurredOnScanCompleted = 'ErrorOccurredOnScanCompleted',
    SevenZipNotFoundOrInstalled = 'SevenZipNotFoundOrInstalled',
    ErrorOccurredOnLaunchScan = 'ErrorOccurredOnLaunchScan',
    InvalidHeader = 'InvalidHeader',
    ErrorOccurredOnPreScanValidation = 'ErrorOccurredOnPreScanValidation',
    RawScanFileExpired = 'RawScanFileExpired',
    SecretsAndEncryptionIntegration = 'SecretsAndEncryptionIntegration',
    ArchiveMethodUnavailable = 'ArchiveMethodUnavailable'
}
/**
* @export
* @enum {string}
*/
export enum ScanTaskModelGlobalThreatLevelEnum {
    Unknown = 'Unknown',
    Secure = 'Secure',
    NeedsAttention = 'NeedsAttention',
    Insecure = 'Insecure',
    Critical = 'Critical'
}
/**
* @export
* @enum {string}
*/
export enum ScanTaskModelPhaseEnum {
    Pending = 'Pending',
    Crawling = 'Crawling',
    CrawlingAndAttacking = 'CrawlingAndAttacking',
    Attacking = 'Attacking',
    ReCrawling = 'ReCrawling',
    Complete = 'Complete'
}
/**
* @export
* @enum {string}
*/
export enum ScanTaskModelScanTypeEnum {
    Full = 'Full',
    Retest = 'Retest',
    Incremental = 'Incremental'
}
/**
* @export
* @enum {string}
*/
export enum ScanTaskModelStateEnum {
    Queued = 'Queued',
    Scanning = 'Scanning',
    Archiving = 'Archiving',
    Complete = 'Complete',
    Failed = 'Failed',
    Cancelled = 'Cancelled',
    Delayed = 'Delayed',
    Pausing = 'Pausing',
    Paused = 'Paused',
    Resuming = 'Resuming',
    AsyncArchiving = 'AsyncArchiving'
}
/**
* @export
* @enum {string}
*/
export enum ScanTaskModelThreatLevelEnum {
    Unknown = 'Unknown',
    Secure = 'Secure',
    NeedsAttention = 'NeedsAttention',
    Insecure = 'Insecure',
    Critical = 'Critical'
}


/**
 * Check if a given object implements the ScanTaskModel interface.
 */
export function instanceOfScanTaskModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function ScanTaskModelFromJSON(json: any): ScanTaskModel {
    return ScanTaskModelFromJSONTyped(json, false);
}

export function ScanTaskModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanTaskModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'additionalWebsites': !exists(json, 'AdditionalWebsites') ? undefined : ((json['AdditionalWebsites'] as Array<any>).map(AdditionalWebsiteModelFromJSON)),
        'agentId': !exists(json, 'AgentId') ? undefined : json['AgentId'],
        'agentName': !exists(json, 'AgentName') ? undefined : json['AgentName'],
        'cookies': !exists(json, 'Cookies') ? undefined : json['Cookies'],
        'crawlAndAttack': !exists(json, 'CrawlAndAttack') ? undefined : json['CrawlAndAttack'],
        'deletedOn': !exists(json, 'DeletedOn') ? undefined : (new Date(json['DeletedOn'])),
        'enableHeuristicChecksInCustomUrlRewrite': !exists(json, 'EnableHeuristicChecksInCustomUrlRewrite') ? undefined : json['EnableHeuristicChecksInCustomUrlRewrite'],
        'excludedLinks': !exists(json, 'ExcludedLinks') ? undefined : json['ExcludedLinks'],
        'excludeLinks': !exists(json, 'ExcludeLinks') ? undefined : json['ExcludeLinks'],
        'disallowedHttpMethods': !exists(json, 'DisallowedHttpMethods') ? undefined : json['DisallowedHttpMethods'],
        'findAndFollowNewLinks': !exists(json, 'FindAndFollowNewLinks') ? undefined : json['FindAndFollowNewLinks'],
        'importedLinks': !exists(json, 'ImportedLinks') ? undefined : json['ImportedLinks'],
        'allImportedLinks': !exists(json, 'AllImportedLinks') ? undefined : json['AllImportedLinks'],
        'desktopScanId': !exists(json, 'DesktopScanId') ? undefined : json['DesktopScanId'],
        'initiatedTime': !exists(json, 'InitiatedTime') ? undefined : json['InitiatedTime'],
        'initiatedDate': !exists(json, 'InitiatedDate') ? undefined : json['InitiatedDate'],
        'initiatedAt': !exists(json, 'InitiatedAt') ? undefined : (new Date(json['InitiatedAt'])),
        'maxDynamicSignatures': !exists(json, 'MaxDynamicSignatures') ? undefined : json['MaxDynamicSignatures'],
        'maxScanDuration': !exists(json, 'MaxScanDuration') ? undefined : json['MaxScanDuration'],
        'duration': !exists(json, 'Duration') ? undefined : json['Duration'],
        'policyDescription': !exists(json, 'PolicyDescription') ? undefined : json['PolicyDescription'],
        'policyId': !exists(json, 'PolicyId') ? undefined : json['PolicyId'],
        'policyUserId': !exists(json, 'PolicyUserId') ? undefined : json['PolicyUserId'],
        'policyIsDefault': !exists(json, 'PolicyIsDefault') ? undefined : json['PolicyIsDefault'],
        'policyIsShared': !exists(json, 'PolicyIsShared') ? undefined : json['PolicyIsShared'],
        'policyName': !exists(json, 'PolicyName') ? undefined : json['PolicyName'],
        'authenticationProfileId': !exists(json, 'AuthenticationProfileId') ? undefined : json['AuthenticationProfileId'],
        'authenticationProfileOption': !exists(json, 'AuthenticationProfileOption') ? undefined : json['AuthenticationProfileOption'],
        'reportPolicyDescription': !exists(json, 'ReportPolicyDescription') ? undefined : json['ReportPolicyDescription'],
        'reportPolicyId': !exists(json, 'ReportPolicyId') ? undefined : json['ReportPolicyId'],
        'reportPolicyUserId': !exists(json, 'ReportPolicyUserId') ? undefined : json['ReportPolicyUserId'],
        'reportPolicyIsDefault': !exists(json, 'ReportPolicyIsDefault') ? undefined : json['ReportPolicyIsDefault'],
        'reportPolicyIsShared': !exists(json, 'ReportPolicyIsShared') ? undefined : json['ReportPolicyIsShared'],
        'reportPolicyName': !exists(json, 'ReportPolicyName') ? undefined : json['ReportPolicyName'],
        'scope': !exists(json, 'Scope') ? undefined : json['Scope'],
        'subPathMaxDynamicSignatures': !exists(json, 'SubPathMaxDynamicSignatures') ? undefined : json['SubPathMaxDynamicSignatures'],
        'targetPath': !exists(json, 'TargetPath') ? undefined : json['TargetPath'],
        'targetUrl': !exists(json, 'TargetUrl') ? undefined : json['TargetUrl'],
        'targetUrlRoot': !exists(json, 'TargetUrlRoot') ? undefined : json['TargetUrlRoot'],
        'timeWindow': !exists(json, 'TimeWindow') ? undefined : ScanTimeWindowModelFromJSON(json['TimeWindow']),
        'totalVulnerabilityCount': !exists(json, 'TotalVulnerabilityCount') ? undefined : json['TotalVulnerabilityCount'],
        'urlRewriteAnalyzableExtensions': !exists(json, 'UrlRewriteAnalyzableExtensions') ? undefined : json['UrlRewriteAnalyzableExtensions'],
        'urlRewriteBlockSeparators': !exists(json, 'UrlRewriteBlockSeparators') ? undefined : json['UrlRewriteBlockSeparators'],
        'urlRewriteMode': !exists(json, 'UrlRewriteMode') ? undefined : json['UrlRewriteMode'],
        'urlRewriteRules': !exists(json, 'UrlRewriteRules') ? undefined : ((json['UrlRewriteRules'] as Array<any>).map(UrlRewriteRuleModelFromJSON)),
        'urlRewriteExcludedLinks': !exists(json, 'UrlRewriteExcludedLinks') ? undefined : ((json['UrlRewriteExcludedLinks'] as Array<any>).map(UrlRewriteExcludedPathModelFromJSON)),
        'userId': !exists(json, 'UserId') ? undefined : json['UserId'],
        'vcsCommitInfo': !exists(json, 'VcsCommitInfo') ? undefined : VcsCommitInfoFromJSON(json['VcsCommitInfo']),
        'websiteName': !exists(json, 'WebsiteName') ? undefined : json['WebsiteName'],
        'websiteUrl': !exists(json, 'WebsiteUrl') ? undefined : json['WebsiteUrl'],
        'websiteDescription': !exists(json, 'WebsiteDescription') ? undefined : json['WebsiteDescription'],
        'websiteProtocol': !exists(json, 'WebsiteProtocol') ? undefined : json['WebsiteProtocol'],
        'websiteIsDeleted': !exists(json, 'WebsiteIsDeleted') ? undefined : json['WebsiteIsDeleted'],
        'isWebsiteLatestCompletedFullScanTask': !exists(json, 'IsWebsiteLatestCompletedFullScanTask') ? undefined : json['IsWebsiteLatestCompletedFullScanTask'],
        'enablePciScanTask': !exists(json, 'EnablePciScanTask') ? undefined : json['EnablePciScanTask'],
        'pciScanTask': !exists(json, 'PciScanTask') ? undefined : PciScanTaskViewModelFromJSON(json['PciScanTask']),
        'userName': !exists(json, 'UserName') ? undefined : json['UserName'],
        'queuedScanTaskExist': !exists(json, 'QueuedScanTaskExist') ? undefined : json['QueuedScanTaskExist'],
        'scanTaskProfileId': !exists(json, 'ScanTaskProfileId') ? undefined : json['ScanTaskProfileId'],
        'scanTaskProfile': !exists(json, 'ScanTaskProfile') ? undefined : ReducedScanTaskProfileFromJSON(json['ScanTaskProfile']),
        'websiteGroupIds': !exists(json, 'WebsiteGroupIds') ? undefined : json['WebsiteGroupIds'],
        'comments': !exists(json, 'Comments') ? undefined : json['Comments'],
        'businessLogicRecorderSetting': !exists(json, 'BusinessLogicRecorderSetting') ? undefined : BusinessLogicRecorderSettingModelFromJSON(json['BusinessLogicRecorderSetting']),
        'scanProfileChanged': !exists(json, 'ScanProfileChanged') ? undefined : json['ScanProfileChanged'],
        'completedSteps': !exists(json, 'CompletedSteps') ? undefined : json['CompletedSteps'],
        'estimatedLaunchTime': !exists(json, 'EstimatedLaunchTime') ? undefined : json['EstimatedLaunchTime'],
        'estimatedSteps': !exists(json, 'EstimatedSteps') ? undefined : json['EstimatedSteps'],
        'failureReason': !exists(json, 'FailureReason') ? undefined : json['FailureReason'],
        'failureReasonDescription': !exists(json, 'FailureReasonDescription') ? undefined : json['FailureReasonDescription'],
        'failureReasonString': !exists(json, 'FailureReasonString') ? undefined : json['FailureReasonString'],
        'globalThreatLevel': !exists(json, 'GlobalThreatLevel') ? undefined : json['GlobalThreatLevel'],
        'globalVulnerabilityCriticalCount': !exists(json, 'GlobalVulnerabilityCriticalCount') ? undefined : json['GlobalVulnerabilityCriticalCount'],
        'globalVulnerabilityHighCount': !exists(json, 'GlobalVulnerabilityHighCount') ? undefined : json['GlobalVulnerabilityHighCount'],
        'globalVulnerabilityInfoCount': !exists(json, 'GlobalVulnerabilityInfoCount') ? undefined : json['GlobalVulnerabilityInfoCount'],
        'globalVulnerabilityBestPracticeCount': !exists(json, 'GlobalVulnerabilityBestPracticeCount') ? undefined : json['GlobalVulnerabilityBestPracticeCount'],
        'globalVulnerabilityLowCount': !exists(json, 'GlobalVulnerabilityLowCount') ? undefined : json['GlobalVulnerabilityLowCount'],
        'globalVulnerabilityMediumCount': !exists(json, 'GlobalVulnerabilityMediumCount') ? undefined : json['GlobalVulnerabilityMediumCount'],
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'isCompleted': !exists(json, 'IsCompleted') ? undefined : json['IsCompleted'],
        'percentage': !exists(json, 'Percentage') ? undefined : json['Percentage'],
        'phase': !exists(json, 'Phase') ? undefined : json['Phase'],
        'scanTaskGroupId': !exists(json, 'ScanTaskGroupId') ? undefined : json['ScanTaskGroupId'],
        'scanType': !exists(json, 'ScanType') ? undefined : json['ScanType'],
        'scheduledScanId': !exists(json, 'ScheduledScanId') ? undefined : json['ScheduledScanId'],
        'state': !exists(json, 'State') ? undefined : json['State'],
        'stateChanged': !exists(json, 'StateChanged') ? undefined : (new Date(json['StateChanged'])),
        'threatLevel': !exists(json, 'ThreatLevel') ? undefined : json['ThreatLevel'],
        'vulnerabilityCriticalCount': !exists(json, 'VulnerabilityCriticalCount') ? undefined : json['VulnerabilityCriticalCount'],
        'vulnerabilityHighCount': !exists(json, 'VulnerabilityHighCount') ? undefined : json['VulnerabilityHighCount'],
        'vulnerabilityInfoCount': !exists(json, 'VulnerabilityInfoCount') ? undefined : json['VulnerabilityInfoCount'],
        'vulnerabilityBestPracticeCount': !exists(json, 'VulnerabilityBestPracticeCount') ? undefined : json['VulnerabilityBestPracticeCount'],
        'vulnerabilityLowCount': !exists(json, 'VulnerabilityLowCount') ? undefined : json['VulnerabilityLowCount'],
        'vulnerabilityMediumCount': !exists(json, 'VulnerabilityMediumCount') ? undefined : json['VulnerabilityMediumCount'],
        'websiteId': !exists(json, 'WebsiteId') ? undefined : json['WebsiteId'],
        'initiated': !exists(json, 'Initiated') ? undefined : (new Date(json['Initiated'])),
        'tags': !exists(json, 'Tags') ? undefined : json['Tags'],
    };
}

export function ScanTaskModelToJSON(value?: ScanTaskModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'AdditionalWebsites': value.additionalWebsites === undefined ? undefined : ((value.additionalWebsites as Array<any>).map(AdditionalWebsiteModelToJSON)),
        'AgentId': value.agentId,
        'AgentName': value.agentName,
        'Cookies': value.cookies,
        'CrawlAndAttack': value.crawlAndAttack,
        'DeletedOn': value.deletedOn === undefined ? undefined : (value.deletedOn.toISOString()),
        'EnableHeuristicChecksInCustomUrlRewrite': value.enableHeuristicChecksInCustomUrlRewrite,
        'ExcludedLinks': value.excludedLinks,
        'ExcludeLinks': value.excludeLinks,
        'DisallowedHttpMethods': value.disallowedHttpMethods,
        'FindAndFollowNewLinks': value.findAndFollowNewLinks,
        'ImportedLinks': value.importedLinks,
        'AllImportedLinks': value.allImportedLinks,
        'DesktopScanId': value.desktopScanId,
        'InitiatedTime': value.initiatedTime,
        'InitiatedDate': value.initiatedDate,
        'InitiatedAt': value.initiatedAt === undefined ? undefined : (value.initiatedAt.toISOString()),
        'MaxDynamicSignatures': value.maxDynamicSignatures,
        'MaxScanDuration': value.maxScanDuration,
        'Duration': value.duration,
        'PolicyDescription': value.policyDescription,
        'PolicyId': value.policyId,
        'PolicyUserId': value.policyUserId,
        'PolicyIsDefault': value.policyIsDefault,
        'PolicyIsShared': value.policyIsShared,
        'PolicyName': value.policyName,
        'AuthenticationProfileId': value.authenticationProfileId,
        'AuthenticationProfileOption': value.authenticationProfileOption,
        'ReportPolicyDescription': value.reportPolicyDescription,
        'ReportPolicyId': value.reportPolicyId,
        'ReportPolicyUserId': value.reportPolicyUserId,
        'ReportPolicyIsDefault': value.reportPolicyIsDefault,
        'ReportPolicyIsShared': value.reportPolicyIsShared,
        'ReportPolicyName': value.reportPolicyName,
        'Scope': value.scope,
        'SubPathMaxDynamicSignatures': value.subPathMaxDynamicSignatures,
        'TargetPath': value.targetPath,
        'TargetUrl': value.targetUrl,
        'TargetUrlRoot': value.targetUrlRoot,
        'TimeWindow': ScanTimeWindowModelToJSON(value.timeWindow),
        'TotalVulnerabilityCount': value.totalVulnerabilityCount,
        'UrlRewriteAnalyzableExtensions': value.urlRewriteAnalyzableExtensions,
        'UrlRewriteBlockSeparators': value.urlRewriteBlockSeparators,
        'UrlRewriteMode': value.urlRewriteMode,
        'UrlRewriteRules': value.urlRewriteRules === undefined ? undefined : ((value.urlRewriteRules as Array<any>).map(UrlRewriteRuleModelToJSON)),
        'UrlRewriteExcludedLinks': value.urlRewriteExcludedLinks === undefined ? undefined : ((value.urlRewriteExcludedLinks as Array<any>).map(UrlRewriteExcludedPathModelToJSON)),
        'UserId': value.userId,
        'VcsCommitInfo': VcsCommitInfoToJSON(value.vcsCommitInfo),
        'WebsiteName': value.websiteName,
        'WebsiteUrl': value.websiteUrl,
        'WebsiteDescription': value.websiteDescription,
        'WebsiteProtocol': value.websiteProtocol,
        'WebsiteIsDeleted': value.websiteIsDeleted,
        'IsWebsiteLatestCompletedFullScanTask': value.isWebsiteLatestCompletedFullScanTask,
        'EnablePciScanTask': value.enablePciScanTask,
        'PciScanTask': PciScanTaskViewModelToJSON(value.pciScanTask),
        'UserName': value.userName,
        'QueuedScanTaskExist': value.queuedScanTaskExist,
        'ScanTaskProfileId': value.scanTaskProfileId,
        'ScanTaskProfile': ReducedScanTaskProfileToJSON(value.scanTaskProfile),
        'WebsiteGroupIds': value.websiteGroupIds,
        'Comments': value.comments,
        'BusinessLogicRecorderSetting': BusinessLogicRecorderSettingModelToJSON(value.businessLogicRecorderSetting),
        'ScanProfileChanged': value.scanProfileChanged,
        'CompletedSteps': value.completedSteps,
        'EstimatedLaunchTime': value.estimatedLaunchTime,
        'EstimatedSteps': value.estimatedSteps,
        'FailureReason': value.failureReason,
        'FailureReasonDescription': value.failureReasonDescription,
        'GlobalThreatLevel': value.globalThreatLevel,
        'GlobalVulnerabilityCriticalCount': value.globalVulnerabilityCriticalCount,
        'GlobalVulnerabilityHighCount': value.globalVulnerabilityHighCount,
        'GlobalVulnerabilityInfoCount': value.globalVulnerabilityInfoCount,
        'GlobalVulnerabilityBestPracticeCount': value.globalVulnerabilityBestPracticeCount,
        'GlobalVulnerabilityLowCount': value.globalVulnerabilityLowCount,
        'GlobalVulnerabilityMediumCount': value.globalVulnerabilityMediumCount,
        'Id': value.id,
        'Phase': value.phase,
        'ScanTaskGroupId': value.scanTaskGroupId,
        'ScanType': value.scanType,
        'ScheduledScanId': value.scheduledScanId,
        'State': value.state,
        'StateChanged': value.stateChanged === undefined ? undefined : (value.stateChanged.toISOString()),
        'ThreatLevel': value.threatLevel,
        'VulnerabilityCriticalCount': value.vulnerabilityCriticalCount,
        'VulnerabilityHighCount': value.vulnerabilityHighCount,
        'VulnerabilityInfoCount': value.vulnerabilityInfoCount,
        'VulnerabilityBestPracticeCount': value.vulnerabilityBestPracticeCount,
        'VulnerabilityLowCount': value.vulnerabilityLowCount,
        'VulnerabilityMediumCount': value.vulnerabilityMediumCount,
        'WebsiteId': value.websiteId,
        'Initiated': value.initiated === undefined ? undefined : (value.initiated.toISOString()),
        'Tags': value.tags,
    };
}

