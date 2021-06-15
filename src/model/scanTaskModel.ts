/**
 * Netsparker Enterprise API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { RequestFile } from './models';
import { AdditionalWebsiteModel } from './additionalWebsiteModel';
import { PciScanTaskViewModel } from './pciScanTaskViewModel';
import { ReducedScanTaskProfile } from './reducedScanTaskProfile';
import { ScanTimeWindowModel } from './scanTimeWindowModel';
import { UrlRewriteExcludedPathModel } from './urlRewriteExcludedPathModel';
import { UrlRewriteRuleModel } from './urlRewriteRuleModel';
import { VcsCommitInfo } from './vcsCommitInfo';

/**
* Represents a model for carrying {Invicti.Cloud.Core.Models.ScanTask} content.
*/
export class ScanTaskModel {
    /**
    * Gets or sets the additional websites to scan.
    */
    'additionalWebsites'?: Array<AdditionalWebsiteModel>;
    /**
    * Gets or sets the agent id.
    */
    'agentId'?: string;
    /**
    * Gets or sets the agent name.
    */
    'agentName'?: string;
    /**
    * Gets or sets the cookies.
    */
    'cookies'?: string;
    /**
    * Gets or sets a value indicating whether parallel attacker is enabled.
    */
    'crawlAndAttack'?: boolean;
    /**
    * Gets or sets a value indicating whether Heuristic URL Rewrite support is enabled together with custom URL Rewrite  support.
    */
    'enableHeuristicChecksInCustomUrlRewrite'?: boolean;
    /**
    * Gets or sets the excluded links.
    */
    'excludedLinks'?: string;
    /**
    * Gets or sets a value indicating whether links should be excluded/included.
    */
    'excludeLinks'?: boolean;
    /**
    * Gets or sets the disallowed HTTP methods.
    */
    'disallowedHttpMethods'?: string;
    /**
    * Gets or sets a value indicating whether automatic crawling is enabled.
    */
    'findAndFollowNewLinks'?: boolean;
    /**
    * Gets or sets the imported links.
    */
    'importedLinks'?: string;
    /**
    * Gets the desktop scan identifier.
    */
    'desktopScanId'?: string;
    /**
    * Gets or sets initiated date in user\'s preferred format.
    */
    'initiatedTime'?: string;
    /**
    * Gets or sets the initiated date in user\'s preferred format.
    */
    'initiatedDate'?: string;
    /**
    * Gets or sets the initiated date.
    */
    'initiatedAt'?: Date;
    /**
    * Gets or sets the root path maximum dynamic signatures for heuristic URL Rewrite detection.
    */
    'maxDynamicSignatures'?: number;
    /**
    * Gets or sets the maximum duration of the scan in hours.
    */
    'maxScanDuration'?: number;
    /**
    * Gets or sets the duration
    */
    'duration'?: string;
    /**
    * Gets or sets the description of the policy.
    */
    'policyDescription'?: string;
    /**
    * Gets or sets the foreign key reference to the related Policy instance.
    */
    'policyId'?: string;
    /**
    * Gets or sets the name of the policy.
    */
    'policyName'?: string;
    /**
    * Gets or sets the foreign key reference to the related Authentication Profile instance.
    */
    'authenticationProfileId'?: string;
    /**
    * Gets or sets the the authentication profile option.
    */
    'authenticationProfileOption'?: ScanTaskModel.AuthenticationProfileOptionEnum;
    /**
    * Gets or sets the description of the report policy.
    */
    'reportPolicyDescription'?: string;
    /**
    * Gets or sets the foreign key reference to the related {Invicti.Cloud.Core.Models.ReportPolicySetting} instance.
    */
    'reportPolicyId'?: string;
    /**
    * Gets or sets the name of the report policy.
    */
    'reportPolicyName'?: string;
    /**
    * Gets or sets the scan scope.
    */
    'scope'?: ScanTaskModel.ScopeEnum;
    /**
    * Gets or sets the sub path maximum dynamic signatures for heuristic URL Rewrite detection.
    */
    'subPathMaxDynamicSignatures'?: number;
    /**
    * Gets or sets target path.
    */
    'targetPath'?: string;
    /**
    * Gets or sets TargetUrl.
    */
    'targetUrl'?: string;
    /**
    * Gets or sets the target URL root.
    */
    'targetUrlRoot'?: string;
    'timeWindow'?: ScanTimeWindowModel;
    /**
    * Gets or sets the total vulnerability count without information vulnerabilities.
    */
    'totalVulnerabilityCount'?: number;
    /**
    * Gets or sets the extensions that will be analyzed for heuristic URL Rewrite detection.
    */
    'urlRewriteAnalyzableExtensions'?: string;
    /**
    * Gets or sets the block separators for heuristic URL Rewrite detection.
    */
    'urlRewriteBlockSeparators'?: string;
    /**
    * Gets or sets the URL Rewrite mode.
    */
    'urlRewriteMode'?: ScanTaskModel.UrlRewriteModeEnum;
    /**
    * Gets or sets the URL Rewrite rules.
    */
    'urlRewriteRules'?: Array<UrlRewriteRuleModel>;
    /**
    * Gets or sets the URL rewrite excluded links.
    */
    'urlRewriteExcludedLinks'?: Array<UrlRewriteExcludedPathModel>;
    /**
    * Gets or sets the user identifier.
    */
    'userId'?: string;
    'vcsCommitInfo'?: VcsCommitInfo;
    /**
    * Gets or sets the name of the website.
    */
    'websiteName'?: string;
    /**
    * Gets or sets the website URL.
    */
    'websiteUrl'?: string;
    /**
    * Gets or sets the description of the website.
    */
    'websiteDescription'?: string;
    /**
    * Gets or sets the pci scan task is enabled.
    */
    'enablePciScanTask'?: boolean;
    'pciScanTask'?: PciScanTaskViewModel;
    /**
    * Gets or sets the user\'s name.
    */
    'userName'?: string;
    /**
    * Determines whether if the scan task model has initiated queued scan.
    */
    'queuedScanTaskExist'?: boolean;
    /**
    * Gets or sets the scan task profile id
    */
    'scanTaskProfileId'?: string;
    'scanTaskProfile'?: ReducedScanTaskProfile;
    /**
    * The group ids of website in it
    */
    'websiteGroupIds'?: Array<string>;
    /**
    * Gets or sets the number of steps (HTTP requests) completed thus far.
    */
    'completedSteps'?: number;
    /**
    * Gets or sets the estimated launch time in minutes for queued scans.
    */
    'estimatedLaunchTime'?: number;
    /**
    * Gets or sets the estimated total number of steps (HTTP requests) that this scan will undertake.
    */
    'estimatedSteps'?: number;
    /**
    * Gets or sets FailureReason
    */
    'failureReason'?: ScanTaskModel.FailureReasonEnum;
    /**
    * Gets the failure reason description.
    */
    'failureReasonDescription'?: string;
    /**
    * Gets the failure reason string.
    */
    'failureReasonString'?: string;
    /**
    * Gets or sets the global threat level.
    */
    'globalThreatLevel'?: ScanTaskModel.GlobalThreatLevelEnum;
    /**
    * Gets the global vulnerability critical count.
    */
    'globalVulnerabilityCriticalCount'?: number;
    /**
    * Gets the global vulnerability high count.
    */
    'globalVulnerabilityHighCount'?: number;
    /**
    * Gets the global vulnerability information count.
    */
    'globalVulnerabilityInfoCount'?: number;
    /**
    * Gets the global vulnerability information count.
    */
    'globalVulnerabilityBestPracticeCount'?: number;
    /**
    * Gets the global vulnerability low count.
    */
    'globalVulnerabilityLowCount'?: number;
    /**
    * Gets the global vulnerability medium count.
    */
    'globalVulnerabilityMediumCount'?: number;
    /**
    * Gets or sets Id.
    */
    'id'?: string;
    /**
    * Gets a value indicating whether scan is completed  with any state.
    */
    'isCompleted'?: boolean;
    /**
    * Gets the completed percentage.
    */
    'percentage'?: number;
    /**
    * Gets or sets the Phase.
    */
    'phase'?: ScanTaskModel.PhaseEnum;
    /**
    * Gets or sets the scan group identifier.
    */
    'scanTaskGroupId'?: string;
    /**
    * Gets or sets the type of the scan.
    */
    'scanType'?: ScanTaskModel.ScanTypeEnum;
    /**
    * Gets or sets the scheduled scan identifier.
    */
    'scheduledScanId'?: string;
    /**
    * Gets or sets State.
    */
    'state'?: ScanTaskModel.StateEnum;
    /**
    * Gets or sets the date and time at which this task state was last changed.
    */
    'stateChanged'?: Date;
    /**
    * Gets or sets the threat level.
    */
    'threatLevel'?: ScanTaskModel.ThreatLevelEnum;
    /**
    * Gets or sets the count of vulnerabilities with critical level severity.
    */
    'vulnerabilityCriticalCount'?: number;
    /**
    * Gets or sets the count of vulnerabilities with high level severity.
    */
    'vulnerabilityHighCount'?: number;
    /**
    * Gets or sets the count of vulnerabilities with information level severity.
    */
    'vulnerabilityInfoCount'?: number;
    /**
    * Gets or sets the count of vulnerabilities with best practice level severity.
    */
    'vulnerabilityBestPracticeCount'?: number;
    /**
    * Gets or sets the count of vulnerabilities with low level severity.
    */
    'vulnerabilityLowCount'?: number;
    /**
    * Gets or sets the count of vulnerabilities with medium level severity.
    */
    'vulnerabilityMediumCount'?: number;
    /**
    * Gets the website identifier.
    */
    'websiteId'?: string;
    /**
    * Date and time at which this task was initiated.
    */
    'initiated'?: Date;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "additionalWebsites",
            "baseName": "AdditionalWebsites",
            "type": "Array<AdditionalWebsiteModel>"
        },
        {
            "name": "agentId",
            "baseName": "AgentId",
            "type": "string"
        },
        {
            "name": "agentName",
            "baseName": "AgentName",
            "type": "string"
        },
        {
            "name": "cookies",
            "baseName": "Cookies",
            "type": "string"
        },
        {
            "name": "crawlAndAttack",
            "baseName": "CrawlAndAttack",
            "type": "boolean"
        },
        {
            "name": "enableHeuristicChecksInCustomUrlRewrite",
            "baseName": "EnableHeuristicChecksInCustomUrlRewrite",
            "type": "boolean"
        },
        {
            "name": "excludedLinks",
            "baseName": "ExcludedLinks",
            "type": "string"
        },
        {
            "name": "excludeLinks",
            "baseName": "ExcludeLinks",
            "type": "boolean"
        },
        {
            "name": "disallowedHttpMethods",
            "baseName": "DisallowedHttpMethods",
            "type": "string"
        },
        {
            "name": "findAndFollowNewLinks",
            "baseName": "FindAndFollowNewLinks",
            "type": "boolean"
        },
        {
            "name": "importedLinks",
            "baseName": "ImportedLinks",
            "type": "string"
        },
        {
            "name": "desktopScanId",
            "baseName": "DesktopScanId",
            "type": "string"
        },
        {
            "name": "initiatedTime",
            "baseName": "InitiatedTime",
            "type": "string"
        },
        {
            "name": "initiatedDate",
            "baseName": "InitiatedDate",
            "type": "string"
        },
        {
            "name": "initiatedAt",
            "baseName": "InitiatedAt",
            "type": "Date"
        },
        {
            "name": "maxDynamicSignatures",
            "baseName": "MaxDynamicSignatures",
            "type": "number"
        },
        {
            "name": "maxScanDuration",
            "baseName": "MaxScanDuration",
            "type": "number"
        },
        {
            "name": "duration",
            "baseName": "Duration",
            "type": "string"
        },
        {
            "name": "policyDescription",
            "baseName": "PolicyDescription",
            "type": "string"
        },
        {
            "name": "policyId",
            "baseName": "PolicyId",
            "type": "string"
        },
        {
            "name": "policyName",
            "baseName": "PolicyName",
            "type": "string"
        },
        {
            "name": "authenticationProfileId",
            "baseName": "AuthenticationProfileId",
            "type": "string"
        },
        {
            "name": "authenticationProfileOption",
            "baseName": "AuthenticationProfileOption",
            "type": "ScanTaskModel.AuthenticationProfileOptionEnum"
        },
        {
            "name": "reportPolicyDescription",
            "baseName": "ReportPolicyDescription",
            "type": "string"
        },
        {
            "name": "reportPolicyId",
            "baseName": "ReportPolicyId",
            "type": "string"
        },
        {
            "name": "reportPolicyName",
            "baseName": "ReportPolicyName",
            "type": "string"
        },
        {
            "name": "scope",
            "baseName": "Scope",
            "type": "ScanTaskModel.ScopeEnum"
        },
        {
            "name": "subPathMaxDynamicSignatures",
            "baseName": "SubPathMaxDynamicSignatures",
            "type": "number"
        },
        {
            "name": "targetPath",
            "baseName": "TargetPath",
            "type": "string"
        },
        {
            "name": "targetUrl",
            "baseName": "TargetUrl",
            "type": "string"
        },
        {
            "name": "targetUrlRoot",
            "baseName": "TargetUrlRoot",
            "type": "string"
        },
        {
            "name": "timeWindow",
            "baseName": "TimeWindow",
            "type": "ScanTimeWindowModel"
        },
        {
            "name": "totalVulnerabilityCount",
            "baseName": "TotalVulnerabilityCount",
            "type": "number"
        },
        {
            "name": "urlRewriteAnalyzableExtensions",
            "baseName": "UrlRewriteAnalyzableExtensions",
            "type": "string"
        },
        {
            "name": "urlRewriteBlockSeparators",
            "baseName": "UrlRewriteBlockSeparators",
            "type": "string"
        },
        {
            "name": "urlRewriteMode",
            "baseName": "UrlRewriteMode",
            "type": "ScanTaskModel.UrlRewriteModeEnum"
        },
        {
            "name": "urlRewriteRules",
            "baseName": "UrlRewriteRules",
            "type": "Array<UrlRewriteRuleModel>"
        },
        {
            "name": "urlRewriteExcludedLinks",
            "baseName": "UrlRewriteExcludedLinks",
            "type": "Array<UrlRewriteExcludedPathModel>"
        },
        {
            "name": "userId",
            "baseName": "UserId",
            "type": "string"
        },
        {
            "name": "vcsCommitInfo",
            "baseName": "VcsCommitInfo",
            "type": "VcsCommitInfo"
        },
        {
            "name": "websiteName",
            "baseName": "WebsiteName",
            "type": "string"
        },
        {
            "name": "websiteUrl",
            "baseName": "WebsiteUrl",
            "type": "string"
        },
        {
            "name": "websiteDescription",
            "baseName": "WebsiteDescription",
            "type": "string"
        },
        {
            "name": "enablePciScanTask",
            "baseName": "EnablePciScanTask",
            "type": "boolean"
        },
        {
            "name": "pciScanTask",
            "baseName": "PciScanTask",
            "type": "PciScanTaskViewModel"
        },
        {
            "name": "userName",
            "baseName": "UserName",
            "type": "string"
        },
        {
            "name": "queuedScanTaskExist",
            "baseName": "QueuedScanTaskExist",
            "type": "boolean"
        },
        {
            "name": "scanTaskProfileId",
            "baseName": "ScanTaskProfileId",
            "type": "string"
        },
        {
            "name": "scanTaskProfile",
            "baseName": "ScanTaskProfile",
            "type": "ReducedScanTaskProfile"
        },
        {
            "name": "websiteGroupIds",
            "baseName": "WebsiteGroupIds",
            "type": "Array<string>"
        },
        {
            "name": "completedSteps",
            "baseName": "CompletedSteps",
            "type": "number"
        },
        {
            "name": "estimatedLaunchTime",
            "baseName": "EstimatedLaunchTime",
            "type": "number"
        },
        {
            "name": "estimatedSteps",
            "baseName": "EstimatedSteps",
            "type": "number"
        },
        {
            "name": "failureReason",
            "baseName": "FailureReason",
            "type": "ScanTaskModel.FailureReasonEnum"
        },
        {
            "name": "failureReasonDescription",
            "baseName": "FailureReasonDescription",
            "type": "string"
        },
        {
            "name": "failureReasonString",
            "baseName": "FailureReasonString",
            "type": "string"
        },
        {
            "name": "globalThreatLevel",
            "baseName": "GlobalThreatLevel",
            "type": "ScanTaskModel.GlobalThreatLevelEnum"
        },
        {
            "name": "globalVulnerabilityCriticalCount",
            "baseName": "GlobalVulnerabilityCriticalCount",
            "type": "number"
        },
        {
            "name": "globalVulnerabilityHighCount",
            "baseName": "GlobalVulnerabilityHighCount",
            "type": "number"
        },
        {
            "name": "globalVulnerabilityInfoCount",
            "baseName": "GlobalVulnerabilityInfoCount",
            "type": "number"
        },
        {
            "name": "globalVulnerabilityBestPracticeCount",
            "baseName": "GlobalVulnerabilityBestPracticeCount",
            "type": "number"
        },
        {
            "name": "globalVulnerabilityLowCount",
            "baseName": "GlobalVulnerabilityLowCount",
            "type": "number"
        },
        {
            "name": "globalVulnerabilityMediumCount",
            "baseName": "GlobalVulnerabilityMediumCount",
            "type": "number"
        },
        {
            "name": "id",
            "baseName": "Id",
            "type": "string"
        },
        {
            "name": "isCompleted",
            "baseName": "IsCompleted",
            "type": "boolean"
        },
        {
            "name": "percentage",
            "baseName": "Percentage",
            "type": "number"
        },
        {
            "name": "phase",
            "baseName": "Phase",
            "type": "ScanTaskModel.PhaseEnum"
        },
        {
            "name": "scanTaskGroupId",
            "baseName": "ScanTaskGroupId",
            "type": "string"
        },
        {
            "name": "scanType",
            "baseName": "ScanType",
            "type": "ScanTaskModel.ScanTypeEnum"
        },
        {
            "name": "scheduledScanId",
            "baseName": "ScheduledScanId",
            "type": "string"
        },
        {
            "name": "state",
            "baseName": "State",
            "type": "ScanTaskModel.StateEnum"
        },
        {
            "name": "stateChanged",
            "baseName": "StateChanged",
            "type": "Date"
        },
        {
            "name": "threatLevel",
            "baseName": "ThreatLevel",
            "type": "ScanTaskModel.ThreatLevelEnum"
        },
        {
            "name": "vulnerabilityCriticalCount",
            "baseName": "VulnerabilityCriticalCount",
            "type": "number"
        },
        {
            "name": "vulnerabilityHighCount",
            "baseName": "VulnerabilityHighCount",
            "type": "number"
        },
        {
            "name": "vulnerabilityInfoCount",
            "baseName": "VulnerabilityInfoCount",
            "type": "number"
        },
        {
            "name": "vulnerabilityBestPracticeCount",
            "baseName": "VulnerabilityBestPracticeCount",
            "type": "number"
        },
        {
            "name": "vulnerabilityLowCount",
            "baseName": "VulnerabilityLowCount",
            "type": "number"
        },
        {
            "name": "vulnerabilityMediumCount",
            "baseName": "VulnerabilityMediumCount",
            "type": "number"
        },
        {
            "name": "websiteId",
            "baseName": "WebsiteId",
            "type": "string"
        },
        {
            "name": "initiated",
            "baseName": "Initiated",
            "type": "Date"
        }    ];

    static getAttributeTypeMap() {
        return ScanTaskModel.attributeTypeMap;
    }
}

export namespace ScanTaskModel {
    export enum AuthenticationProfileOptionEnum {
        DontUse = <any> 'DontUse',
        UseMatchedProfile = <any> 'UseMatchedProfile',
        SelectedProfile = <any> 'SelectedProfile'
    }
    export enum ScopeEnum {
        EnteredPathAndBelow = <any> 'EnteredPathAndBelow',
        OnlyEnteredUrl = <any> 'OnlyEnteredUrl',
        WholeDomain = <any> 'WholeDomain'
    }
    export enum UrlRewriteModeEnum {
        None = <any> 'None',
        Heuristic = <any> 'Heuristic',
        Custom = <any> 'Custom'
    }
    export enum FailureReasonEnum {
        NameResolutionFailure = <any> 'NameResolutionFailure',
        HostUnavailable = <any> 'HostUnavailable',
        ProxyFailure = <any> 'ProxyFailure',
        UnableToLoadScanSession = <any> 'UnableToLoadScanSession',
        AgentNotAvailable = <any> 'AgentNotAvailable',
        ScanNotAllowed = <any> 'ScanNotAllowed',
        MaxLogoutExceeded = <any> 'MaxLogoutExceeded',
        TargetLinkTimeoutDetected = <any> 'TargetLinkTimeoutDetected',
        LoginFailed = <any> 'LoginFailed',
        UnableToFindAutoSaveNdb = <any> 'UnableToFindAutoSaveNdb',
        ScanPolicyNotFound = <any> 'ScanPolicyNotFound',
        ReportPolicyNotFound = <any> 'ReportPolicyNotFound',
        ErrorOccurredOnScanFailed = <any> 'ErrorOccurredOnScanFailed',
        ErrorOccurredOnPause = <any> 'ErrorOccurredOnPause',
        ErrorOccurredOnCancel = <any> 'ErrorOccurredOnCancel',
        ErrorOccurredOnScanCompleted = <any> 'ErrorOccurredOnScanCompleted',
        SevenZipNotFoundOrInstalled = <any> 'SevenZipNotFoundOrInstalled',
        SecurityProtocolTypeNotSupported = <any> 'SecurityProtocolTypeNotSupported',
        ErrorOccurredOnLaunchScan = <any> 'ErrorOccurredOnLaunchScan'
    }
    export enum GlobalThreatLevelEnum {
        Unknown = <any> 'Unknown',
        Secure = <any> 'Secure',
        NeedsAttention = <any> 'NeedsAttention',
        Insecure = <any> 'Insecure',
        Critical = <any> 'Critical'
    }
    export enum PhaseEnum {
        Pending = <any> 'Pending',
        Crawling = <any> 'Crawling',
        CrawlingAndAttacking = <any> 'CrawlingAndAttacking',
        Attacking = <any> 'Attacking',
        ReCrawling = <any> 'ReCrawling',
        Complete = <any> 'Complete'
    }
    export enum ScanTypeEnum {
        Full = <any> 'Full',
        Retest = <any> 'Retest',
        Incremental = <any> 'Incremental'
    }
    export enum StateEnum {
        Queued = <any> 'Queued',
        Scanning = <any> 'Scanning',
        Archiving = <any> 'Archiving',
        Complete = <any> 'Complete',
        Failed = <any> 'Failed',
        Cancelled = <any> 'Cancelled',
        Delayed = <any> 'Delayed',
        Pausing = <any> 'Pausing',
        Paused = <any> 'Paused',
        Resuming = <any> 'Resuming'
    }
    export enum ThreatLevelEnum {
        Unknown = <any> 'Unknown',
        Secure = <any> 'Secure',
        NeedsAttention = <any> 'NeedsAttention',
        Insecure = <any> 'Insecure',
        Critical = <any> 'Critical'
    }
}
