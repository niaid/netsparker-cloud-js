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

import { mapValues } from '../runtime';
import type { HeaderAuthenticationModel } from './HeaderAuthenticationModel';
import {
    HeaderAuthenticationModelFromJSON,
    HeaderAuthenticationModelFromJSONTyped,
    HeaderAuthenticationModelToJSON,
} from './HeaderAuthenticationModel';
import type { ExcludedLinkModel } from './ExcludedLinkModel';
import {
    ExcludedLinkModelFromJSON,
    ExcludedLinkModelFromJSONTyped,
    ExcludedLinkModelToJSON,
} from './ExcludedLinkModel';
import type { PreRequestScriptSettingModel } from './PreRequestScriptSettingModel';
import {
    PreRequestScriptSettingModelFromJSON,
    PreRequestScriptSettingModelFromJSONTyped,
    PreRequestScriptSettingModelToJSON,
} from './PreRequestScriptSettingModel';
import type { FormAuthenticationSettingModel } from './FormAuthenticationSettingModel';
import {
    FormAuthenticationSettingModelFromJSON,
    FormAuthenticationSettingModelFromJSONTyped,
    FormAuthenticationSettingModelToJSON,
} from './FormAuthenticationSettingModel';
import type { ApiFile } from './ApiFile';
import {
    ApiFileFromJSON,
    ApiFileFromJSONTyped,
    ApiFileToJSON,
} from './ApiFile';
import type { OAuth2SettingApiModel } from './OAuth2SettingApiModel';
import {
    OAuth2SettingApiModelFromJSON,
    OAuth2SettingApiModelFromJSONTyped,
    OAuth2SettingApiModelToJSON,
} from './OAuth2SettingApiModel';
import type { ScheduledScanRecurrenceApiModel } from './ScheduledScanRecurrenceApiModel';
import {
    ScheduledScanRecurrenceApiModelFromJSON,
    ScheduledScanRecurrenceApiModelFromJSONTyped,
    ScheduledScanRecurrenceApiModelToJSON,
} from './ScheduledScanRecurrenceApiModel';
import type { BusinessLogicRecorderSettingModel } from './BusinessLogicRecorderSettingModel';
import {
    BusinessLogicRecorderSettingModelFromJSON,
    BusinessLogicRecorderSettingModelFromJSONTyped,
    BusinessLogicRecorderSettingModelToJSON,
} from './BusinessLogicRecorderSettingModel';
import type { AdditionalWebsiteModel } from './AdditionalWebsiteModel';
import {
    AdditionalWebsiteModelFromJSON,
    AdditionalWebsiteModelFromJSONTyped,
    AdditionalWebsiteModelToJSON,
} from './AdditionalWebsiteModel';
import type { ExcludedUsageTrackerModel } from './ExcludedUsageTrackerModel';
import {
    ExcludedUsageTrackerModelFromJSON,
    ExcludedUsageTrackerModelFromJSONTyped,
    ExcludedUsageTrackerModelToJSON,
} from './ExcludedUsageTrackerModel';
import type { ClientCertificateAuthenticationApiModel } from './ClientCertificateAuthenticationApiModel';
import {
    ClientCertificateAuthenticationApiModelFromJSON,
    ClientCertificateAuthenticationApiModelFromJSONTyped,
    ClientCertificateAuthenticationApiModelToJSON,
} from './ClientCertificateAuthenticationApiModel';
import type { BasicAuthenticationSettingModel } from './BasicAuthenticationSettingModel';
import {
    BasicAuthenticationSettingModelFromJSON,
    BasicAuthenticationSettingModelFromJSONTyped,
    BasicAuthenticationSettingModelToJSON,
} from './BasicAuthenticationSettingModel';
import type { UrlRewriteRuleModel } from './UrlRewriteRuleModel';
import {
    UrlRewriteRuleModelFromJSON,
    UrlRewriteRuleModelFromJSONTyped,
    UrlRewriteRuleModelToJSON,
} from './UrlRewriteRuleModel';
import type { SharkModel } from './SharkModel';
import {
    SharkModelFromJSON,
    SharkModelFromJSONTyped,
    SharkModelToJSON,
} from './SharkModel';
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
     * @type {Array<ApiFile>}
     * @memberof UpdateScheduledScanApiModel
     */
    importedFiles?: Array<ApiFile>;
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
export const UpdateScheduledScanApiModelScheduleRunTypeEnum = {
    Once: 'Once',
    Daily: 'Daily',
    Weekly: 'Weekly',
    Monthly: 'Monthly',
    Quarterly: 'Quarterly',
    Biannually: 'Biannually',
    Yearly: 'Yearly',
    Custom: 'Custom'
} as const;
export type UpdateScheduledScanApiModelScheduleRunTypeEnum = typeof UpdateScheduledScanApiModelScheduleRunTypeEnum[keyof typeof UpdateScheduledScanApiModelScheduleRunTypeEnum];

/**
 * @export
 */
export const UpdateScheduledScanApiModelCreateTypeEnum = {
    Website: 'Website',
    WebsiteGroup: 'WebsiteGroup'
} as const;
export type UpdateScheduledScanApiModelCreateTypeEnum = typeof UpdateScheduledScanApiModelCreateTypeEnum[keyof typeof UpdateScheduledScanApiModelCreateTypeEnum];

/**
 * @export
 */
export const UpdateScheduledScanApiModelDisallowedHttpMethodsEnum = {
    Get: 'GET',
    Post: 'POST',
    Connect: 'CONNECT',
    Head: 'HEAD',
    Trace: 'TRACE',
    Debug: 'DEBUG',
    Track: 'TRACK',
    Put: 'PUT',
    Options: 'OPTIONS',
    Delete: 'DELETE',
    Link: 'LINK',
    Unlink: 'UNLINK',
    Patch: 'PATCH'
} as const;
export type UpdateScheduledScanApiModelDisallowedHttpMethodsEnum = typeof UpdateScheduledScanApiModelDisallowedHttpMethodsEnum[keyof typeof UpdateScheduledScanApiModelDisallowedHttpMethodsEnum];

/**
 * @export
 */
export const UpdateScheduledScanApiModelAuthenticationProfileOptionEnum = {
    DontUse: 'DontUse',
    UseMatchedProfile: 'UseMatchedProfile',
    SelectedProfile: 'SelectedProfile'
} as const;
export type UpdateScheduledScanApiModelAuthenticationProfileOptionEnum = typeof UpdateScheduledScanApiModelAuthenticationProfileOptionEnum[keyof typeof UpdateScheduledScanApiModelAuthenticationProfileOptionEnum];

/**
 * @export
 */
export const UpdateScheduledScanApiModelScopeEnum = {
    EnteredPathAndBelow: 'EnteredPathAndBelow',
    OnlyEnteredUrl: 'OnlyEnteredUrl',
    WholeDomain: 'WholeDomain'
} as const;
export type UpdateScheduledScanApiModelScopeEnum = typeof UpdateScheduledScanApiModelScopeEnum[keyof typeof UpdateScheduledScanApiModelScopeEnum];

/**
 * @export
 */
export const UpdateScheduledScanApiModelUrlRewriteModeEnum = {
    None: 'None',
    Heuristic: 'Heuristic',
    Custom: 'Custom'
} as const;
export type UpdateScheduledScanApiModelUrlRewriteModeEnum = typeof UpdateScheduledScanApiModelUrlRewriteModeEnum[keyof typeof UpdateScheduledScanApiModelUrlRewriteModeEnum];


/**
 * Check if a given object implements the UpdateScheduledScanApiModel interface.
 */
export function instanceOfUpdateScheduledScanApiModel(value: object): boolean {
    if (!('id' in value)) return false;
    if (!('name' in value)) return false;
    if (!('nextExecutionTime' in value)) return false;
    if (!('scheduleRunType' in value)) return false;
    return true;
}

export function UpdateScheduledScanApiModelFromJSON(json: any): UpdateScheduledScanApiModel {
    return UpdateScheduledScanApiModelFromJSONTyped(json, false);
}

export function UpdateScheduledScanApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateScheduledScanApiModel {
    if (json == null) {
        return json;
    }
    return {
        
        'disabled': json['Disabled'] == null ? undefined : json['Disabled'],
        'id': json['Id'],
        'name': json['Name'],
        'nextExecutionTime': json['NextExecutionTime'],
        'scheduleRunType': json['ScheduleRunType'],
        'customRecurrence': json['CustomRecurrence'] == null ? undefined : ScheduledScanRecurrenceApiModelFromJSON(json['CustomRecurrence']),
        'targetUri': json['TargetUri'] == null ? undefined : json['TargetUri'],
        'isTargetUrlRequired': json['IsTargetUrlRequired'] == null ? undefined : json['IsTargetUrlRequired'],
        'createType': json['CreateType'] == null ? undefined : json['CreateType'],
        'websiteGroupId': json['WebsiteGroupId'] == null ? undefined : json['WebsiteGroupId'],
        'additionalWebsites': json['AdditionalWebsites'] == null ? undefined : ((json['AdditionalWebsites'] as Array<any>).map(AdditionalWebsiteModelFromJSON)),
        'basicAuthenticationApiModel': json['BasicAuthenticationApiModel'] == null ? undefined : BasicAuthenticationSettingModelFromJSON(json['BasicAuthenticationApiModel']),
        'clientCertificateAuthenticationSetting': json['ClientCertificateAuthenticationSetting'] == null ? undefined : ClientCertificateAuthenticationApiModelFromJSON(json['ClientCertificateAuthenticationSetting']),
        'cookies': json['Cookies'] == null ? undefined : json['Cookies'],
        'crawlAndAttack': json['CrawlAndAttack'] == null ? undefined : json['CrawlAndAttack'],
        'enableHeuristicChecksInCustomUrlRewrite': json['EnableHeuristicChecksInCustomUrlRewrite'] == null ? undefined : json['EnableHeuristicChecksInCustomUrlRewrite'],
        'excludedLinks': json['ExcludedLinks'] == null ? undefined : ((json['ExcludedLinks'] as Array<any>).map(ExcludedLinkModelFromJSON)),
        'excludedUsageTrackers': json['ExcludedUsageTrackers'] == null ? undefined : ((json['ExcludedUsageTrackers'] as Array<any>).map(ExcludedUsageTrackerModelFromJSON)),
        'disallowedHttpMethods': json['DisallowedHttpMethods'] == null ? undefined : json['DisallowedHttpMethods'],
        'excludeLinks': json['ExcludeLinks'] == null ? undefined : json['ExcludeLinks'],
        'excludeAuthenticationPages': json['ExcludeAuthenticationPages'] == null ? undefined : json['ExcludeAuthenticationPages'],
        'findAndFollowNewLinks': json['FindAndFollowNewLinks'] == null ? undefined : json['FindAndFollowNewLinks'],
        'formAuthenticationSettingModel': json['FormAuthenticationSettingModel'] == null ? undefined : FormAuthenticationSettingModelFromJSON(json['FormAuthenticationSettingModel']),
        'headerAuthentication': json['HeaderAuthentication'] == null ? undefined : HeaderAuthenticationModelFromJSON(json['HeaderAuthentication']),
        'sharkSetting': json['SharkSetting'] == null ? undefined : SharkModelFromJSON(json['SharkSetting']),
        'authenticationProfileOption': json['AuthenticationProfileOption'] == null ? undefined : json['AuthenticationProfileOption'],
        'authenticationProfileId': json['AuthenticationProfileId'] == null ? undefined : json['AuthenticationProfileId'],
        'importedLinks': json['ImportedLinks'] == null ? undefined : json['ImportedLinks'],
        'importedFiles': json['ImportedFiles'] == null ? undefined : ((json['ImportedFiles'] as Array<any>).map(ApiFileFromJSON)),
        'isMaxScanDurationEnabled': json['IsMaxScanDurationEnabled'] == null ? undefined : json['IsMaxScanDurationEnabled'],
        'maxDynamicSignatures': json['MaxDynamicSignatures'] == null ? undefined : json['MaxDynamicSignatures'],
        'maxScanDuration': json['MaxScanDuration'] == null ? undefined : json['MaxScanDuration'],
        'policyId': json['PolicyId'] == null ? undefined : json['PolicyId'],
        'reportPolicyId': json['ReportPolicyId'] == null ? undefined : json['ReportPolicyId'],
        'scope': json['Scope'] == null ? undefined : json['Scope'],
        'subPathMaxDynamicSignatures': json['SubPathMaxDynamicSignatures'] == null ? undefined : json['SubPathMaxDynamicSignatures'],
        'timeWindow': json['TimeWindow'] == null ? undefined : ScanTimeWindowModelFromJSON(json['TimeWindow']),
        'urlRewriteAnalyzableExtensions': json['UrlRewriteAnalyzableExtensions'] == null ? undefined : json['UrlRewriteAnalyzableExtensions'],
        'urlRewriteBlockSeparators': json['UrlRewriteBlockSeparators'] == null ? undefined : json['UrlRewriteBlockSeparators'],
        'urlRewriteMode': json['UrlRewriteMode'] == null ? undefined : json['UrlRewriteMode'],
        'urlRewriteRules': json['UrlRewriteRules'] == null ? undefined : ((json['UrlRewriteRules'] as Array<any>).map(UrlRewriteRuleModelFromJSON)),
        'preRequestScriptSetting': json['PreRequestScriptSetting'] == null ? undefined : PreRequestScriptSettingModelFromJSON(json['PreRequestScriptSetting']),
        'doNotDifferentiateProtocols': json['DoNotDifferentiateProtocols'] == null ? undefined : json['DoNotDifferentiateProtocols'],
        'urlRewriteExcludedLinks': json['UrlRewriteExcludedLinks'] == null ? undefined : ((json['UrlRewriteExcludedLinks'] as Array<any>).map(UrlRewriteExcludedPathModelFromJSON)),
        'oAuth2SettingModel': json['OAuth2SettingModel'] == null ? undefined : OAuth2SettingApiModelFromJSON(json['OAuth2SettingModel']),
        'enablePciScanTask': json['EnablePciScanTask'] == null ? undefined : json['EnablePciScanTask'],
        'businessLogicRecorderSetting': json['BusinessLogicRecorderSetting'] == null ? undefined : BusinessLogicRecorderSettingModelFromJSON(json['BusinessLogicRecorderSetting']),
        'tags': json['Tags'] == null ? undefined : json['Tags'],
        'comments': json['Comments'] == null ? undefined : json['Comments'],
    };
}

export function UpdateScheduledScanApiModelToJSON(value?: Omit<UpdateScheduledScanApiModel, 'IsTargetUrlRequired'> | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Disabled': value['disabled'],
        'Id': value['id'],
        'Name': value['name'],
        'NextExecutionTime': value['nextExecutionTime'],
        'ScheduleRunType': value['scheduleRunType'],
        'CustomRecurrence': ScheduledScanRecurrenceApiModelToJSON(value['customRecurrence']),
        'TargetUri': value['targetUri'],
        'CreateType': value['createType'],
        'WebsiteGroupId': value['websiteGroupId'],
        'AdditionalWebsites': value['additionalWebsites'] == null ? undefined : ((value['additionalWebsites'] as Array<any>).map(AdditionalWebsiteModelToJSON)),
        'BasicAuthenticationApiModel': BasicAuthenticationSettingModelToJSON(value['basicAuthenticationApiModel']),
        'ClientCertificateAuthenticationSetting': ClientCertificateAuthenticationApiModelToJSON(value['clientCertificateAuthenticationSetting']),
        'Cookies': value['cookies'],
        'CrawlAndAttack': value['crawlAndAttack'],
        'EnableHeuristicChecksInCustomUrlRewrite': value['enableHeuristicChecksInCustomUrlRewrite'],
        'ExcludedLinks': value['excludedLinks'] == null ? undefined : ((value['excludedLinks'] as Array<any>).map(ExcludedLinkModelToJSON)),
        'ExcludedUsageTrackers': value['excludedUsageTrackers'] == null ? undefined : ((value['excludedUsageTrackers'] as Array<any>).map(ExcludedUsageTrackerModelToJSON)),
        'DisallowedHttpMethods': value['disallowedHttpMethods'],
        'ExcludeLinks': value['excludeLinks'],
        'ExcludeAuthenticationPages': value['excludeAuthenticationPages'],
        'FindAndFollowNewLinks': value['findAndFollowNewLinks'],
        'FormAuthenticationSettingModel': FormAuthenticationSettingModelToJSON(value['formAuthenticationSettingModel']),
        'HeaderAuthentication': HeaderAuthenticationModelToJSON(value['headerAuthentication']),
        'SharkSetting': SharkModelToJSON(value['sharkSetting']),
        'AuthenticationProfileOption': value['authenticationProfileOption'],
        'AuthenticationProfileId': value['authenticationProfileId'],
        'ImportedLinks': value['importedLinks'],
        'ImportedFiles': value['importedFiles'] == null ? undefined : ((value['importedFiles'] as Array<any>).map(ApiFileToJSON)),
        'IsMaxScanDurationEnabled': value['isMaxScanDurationEnabled'],
        'MaxDynamicSignatures': value['maxDynamicSignatures'],
        'MaxScanDuration': value['maxScanDuration'],
        'PolicyId': value['policyId'],
        'ReportPolicyId': value['reportPolicyId'],
        'Scope': value['scope'],
        'SubPathMaxDynamicSignatures': value['subPathMaxDynamicSignatures'],
        'TimeWindow': ScanTimeWindowModelToJSON(value['timeWindow']),
        'UrlRewriteAnalyzableExtensions': value['urlRewriteAnalyzableExtensions'],
        'UrlRewriteBlockSeparators': value['urlRewriteBlockSeparators'],
        'UrlRewriteMode': value['urlRewriteMode'],
        'UrlRewriteRules': value['urlRewriteRules'] == null ? undefined : ((value['urlRewriteRules'] as Array<any>).map(UrlRewriteRuleModelToJSON)),
        'PreRequestScriptSetting': PreRequestScriptSettingModelToJSON(value['preRequestScriptSetting']),
        'DoNotDifferentiateProtocols': value['doNotDifferentiateProtocols'],
        'UrlRewriteExcludedLinks': value['urlRewriteExcludedLinks'] == null ? undefined : ((value['urlRewriteExcludedLinks'] as Array<any>).map(UrlRewriteExcludedPathModelToJSON)),
        'OAuth2SettingModel': OAuth2SettingApiModelToJSON(value['oAuth2SettingModel']),
        'EnablePciScanTask': value['enablePciScanTask'],
        'BusinessLogicRecorderSetting': BusinessLogicRecorderSettingModelToJSON(value['businessLogicRecorderSetting']),
        'Tags': value['tags'],
        'Comments': value['comments'],
    };
}

