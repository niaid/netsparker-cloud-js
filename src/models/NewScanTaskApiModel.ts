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
import type { ApiFileModel } from './ApiFileModel';
import {
    ApiFileModelFromJSON,
    ApiFileModelFromJSONTyped,
    ApiFileModelToJSON,
} from './ApiFileModel';
import type { BasicAuthenticationSettingModel } from './BasicAuthenticationSettingModel';
import {
    BasicAuthenticationSettingModelFromJSON,
    BasicAuthenticationSettingModelFromJSONTyped,
    BasicAuthenticationSettingModelToJSON,
} from './BasicAuthenticationSettingModel';
import type { BusinessLogicRecorderSettingModel } from './BusinessLogicRecorderSettingModel';
import {
    BusinessLogicRecorderSettingModelFromJSON,
    BusinessLogicRecorderSettingModelFromJSONTyped,
    BusinessLogicRecorderSettingModelToJSON,
} from './BusinessLogicRecorderSettingModel';
import type { ClientCertificateAuthenticationApiModel } from './ClientCertificateAuthenticationApiModel';
import {
    ClientCertificateAuthenticationApiModelFromJSON,
    ClientCertificateAuthenticationApiModelFromJSONTyped,
    ClientCertificateAuthenticationApiModelToJSON,
} from './ClientCertificateAuthenticationApiModel';
import type { ExcludedLinkModel } from './ExcludedLinkModel';
import {
    ExcludedLinkModelFromJSON,
    ExcludedLinkModelFromJSONTyped,
    ExcludedLinkModelToJSON,
} from './ExcludedLinkModel';
import type { ExcludedUsageTrackerModel } from './ExcludedUsageTrackerModel';
import {
    ExcludedUsageTrackerModelFromJSON,
    ExcludedUsageTrackerModelFromJSONTyped,
    ExcludedUsageTrackerModelToJSON,
} from './ExcludedUsageTrackerModel';
import type { FormAuthenticationSettingModel } from './FormAuthenticationSettingModel';
import {
    FormAuthenticationSettingModelFromJSON,
    FormAuthenticationSettingModelFromJSONTyped,
    FormAuthenticationSettingModelToJSON,
} from './FormAuthenticationSettingModel';
import type { HeaderAuthenticationModel } from './HeaderAuthenticationModel';
import {
    HeaderAuthenticationModelFromJSON,
    HeaderAuthenticationModelFromJSONTyped,
    HeaderAuthenticationModelToJSON,
} from './HeaderAuthenticationModel';
import type { OAuth2SettingApiModel } from './OAuth2SettingApiModel';
import {
    OAuth2SettingApiModelFromJSON,
    OAuth2SettingApiModelFromJSONTyped,
    OAuth2SettingApiModelToJSON,
} from './OAuth2SettingApiModel';
import type { PreRequestScriptSettingModel } from './PreRequestScriptSettingModel';
import {
    PreRequestScriptSettingModelFromJSON,
    PreRequestScriptSettingModelFromJSONTyped,
    PreRequestScriptSettingModelToJSON,
} from './PreRequestScriptSettingModel';
import type { ScanTimeWindowModel } from './ScanTimeWindowModel';
import {
    ScanTimeWindowModelFromJSON,
    ScanTimeWindowModelFromJSONTyped,
    ScanTimeWindowModelToJSON,
} from './ScanTimeWindowModel';
import type { SharkModel } from './SharkModel';
import {
    SharkModelFromJSON,
    SharkModelFromJSONTyped,
    SharkModelToJSON,
} from './SharkModel';
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

/**
 * Contains properties that required to start scan.
 * @export
 * @interface NewScanTaskApiModel
 */
export interface NewScanTaskApiModel {
    /**
     * Gets or sets the target URI.
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    targetUri?: string;
    /**
     * Gets or sets whether is target URL required.
     * @type {boolean}
     * @memberof NewScanTaskApiModel
     */
    readonly isTargetUrlRequired?: boolean;
    /**
     * Gets or sets the type of the create.
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    createType?: NewScanTaskApiModelCreateTypeEnum;
    /**
     * Gets or sets the website group identifier. This property is required if CreateType is WebsiteGroup
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    websiteGroupId?: string;
    /**
     * Gets or sets the additional websites to scan.
     * @type {Array<AdditionalWebsiteModel>}
     * @memberof NewScanTaskApiModel
     */
    additionalWebsites?: Array<AdditionalWebsiteModel>;
    /**
     * 
     * @type {BasicAuthenticationSettingModel}
     * @memberof NewScanTaskApiModel
     */
    basicAuthenticationApiModel?: BasicAuthenticationSettingModel;
    /**
     * 
     * @type {ClientCertificateAuthenticationApiModel}
     * @memberof NewScanTaskApiModel
     */
    clientCertificateAuthenticationSetting?: ClientCertificateAuthenticationApiModel;
    /**
     * Gets or sets the cookies. Separate multiple cookies with semicolon. Cookie values must be URL encoded. You can use the
     * following format: Cookiename=Value
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    cookies?: string;
    /**
     * Gets or sets a value indicating whether parallel attacker is enabled.
     * Default: true
     * @type {boolean}
     * @memberof NewScanTaskApiModel
     */
    crawlAndAttack?: boolean;
    /**
     * Gets or sets a value indicating whether Heuristic URL Rewrite support is enabled together with custom URL Rewrite
     * support.
     * @type {boolean}
     * @memberof NewScanTaskApiModel
     */
    enableHeuristicChecksInCustomUrlRewrite?: boolean;
    /**
     * Gets or sets the excluded links.
     * Default: "(log|sign)\\-?(out|off)", "exit", "endsession", "gtm\\.js"
     * @type {Array<ExcludedLinkModel>}
     * @memberof NewScanTaskApiModel
     */
    excludedLinks?: Array<ExcludedLinkModel>;
    /**
     * Gets or sets the excluded usage trackers.
     * @type {Array<ExcludedUsageTrackerModel>}
     * @memberof NewScanTaskApiModel
     */
    excludedUsageTrackers?: Array<ExcludedUsageTrackerModel>;
    /**
     * Gets or sets the disallowed http methods.
     * @type {Array<string>}
     * @memberof NewScanTaskApiModel
     */
    disallowedHttpMethods?: Array<NewScanTaskApiModelDisallowedHttpMethodsEnum>;
    /**
     * Gets or sets a value indicating whether links should be excluded/included.
     * Default: <see ref="bool.True" />
     * @type {boolean}
     * @memberof NewScanTaskApiModel
     */
    excludeLinks?: boolean;
    /**
     * Specifies whether the authentication related pages like login, logout etc. should be excluded from the scan.
     * If form authentication is enabled, exclude authentication pages will be set as true. If you want to scan exclude authentication pages please set as false.
     * @type {boolean}
     * @memberof NewScanTaskApiModel
     */
    excludeAuthenticationPages?: boolean;
    /**
     * Gets or sets a value indicating whether automatic crawling is enabled.
     * @type {boolean}
     * @memberof NewScanTaskApiModel
     */
    findAndFollowNewLinks?: boolean;
    /**
     * 
     * @type {FormAuthenticationSettingModel}
     * @memberof NewScanTaskApiModel
     */
    formAuthenticationSettingModel?: FormAuthenticationSettingModel;
    /**
     * 
     * @type {HeaderAuthenticationModel}
     * @memberof NewScanTaskApiModel
     */
    headerAuthentication?: HeaderAuthenticationModel;
    /**
     * 
     * @type {SharkModel}
     * @memberof NewScanTaskApiModel
     */
    sharkSetting?: SharkModel;
    /**
     * Gets or sets the type of the authentication profile option.
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    authenticationProfileOption?: NewScanTaskApiModelAuthenticationProfileOptionEnum;
    /**
     * Gets or sets the type of the authentication profile identifier.
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    authenticationProfileId?: string;
    /**
     * Gets or sets the imported links.
     * @type {Array<string>}
     * @memberof NewScanTaskApiModel
     */
    importedLinks?: Array<string>;
    /**
     * Gets or sets the imported files. If imported files have not contains any URL, the file not added to scan profile.
     * @type {Array<ApiFileModel>}
     * @memberof NewScanTaskApiModel
     */
    importedFiles?: Array<ApiFileModel>;
    /**
     * Gets or sets a value indicating whether max scan duration is enabled.
     * This is only used for scheduled group scan and regular group scan.
     * @type {boolean}
     * @memberof NewScanTaskApiModel
     */
    isMaxScanDurationEnabled?: boolean;
    /**
     * Gets or sets the root path maximum dynamic signatures for heuristic URL Rewrite detection.
     * Default: 60
     * @type {number}
     * @memberof NewScanTaskApiModel
     */
    maxDynamicSignatures?: number;
    /**
     * Gets or sets the maximum duration of the scan in hours.
     * Default: 48 hours
     * @type {number}
     * @memberof NewScanTaskApiModel
     */
    maxScanDuration?: number;
    /**
     * Gets or sets the scan policy identifier.
     * Default: Default Security Checks
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    policyId?: string;
    /**
     * Gets or sets the report policy identifier.
     * Default: Default Report Policy
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    reportPolicyId?: string;
    /**
     * Gets or sets the scan scope.
     * Default: {Invicti.Cloud.Core.Models.ScanTaskScope.EnteredPathAndBelow}
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    scope?: NewScanTaskApiModelScopeEnum;
    /**
     * Gets or sets the sub path maximum dynamic signatures for heuristic URL Rewrite detection.
     * Default: 30
     * @type {number}
     * @memberof NewScanTaskApiModel
     */
    subPathMaxDynamicSignatures?: number;
    /**
     * 
     * @type {ScanTimeWindowModel}
     * @memberof NewScanTaskApiModel
     */
    timeWindow?: ScanTimeWindowModel;
    /**
     * Gets or sets the extensions that will be analyzed for heuristic URL Rewrite detection.
     * Default: htm,html
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    urlRewriteAnalyzableExtensions?: string;
    /**
     * Gets or sets the block separators for heuristic URL Rewrite detection.
     * Default: /_ $.,;|:
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    urlRewriteBlockSeparators?: string;
    /**
     * Gets or sets the URL Rewrite mode.
     * Default: Heuristic
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    urlRewriteMode?: NewScanTaskApiModelUrlRewriteModeEnum;
    /**
     * Gets or sets the URL Rewrite rules.
     * @type {Array<UrlRewriteRuleModel>}
     * @memberof NewScanTaskApiModel
     */
    urlRewriteRules?: Array<UrlRewriteRuleModel>;
    /**
     * 
     * @type {PreRequestScriptSettingModel}
     * @memberof NewScanTaskApiModel
     */
    preRequestScriptSetting?: PreRequestScriptSettingModel;
    /**
     * Gets or sets a value indicating whether http and https protocols are differentiated.
     * @type {boolean}
     * @memberof NewScanTaskApiModel
     */
    doNotDifferentiateProtocols?: boolean;
    /**
     * Gets or sets the URL rewrite excluded links.
     * @type {Array<UrlRewriteExcludedPathModel>}
     * @memberof NewScanTaskApiModel
     */
    urlRewriteExcludedLinks?: Array<UrlRewriteExcludedPathModel>;
    /**
     * 
     * @type {OAuth2SettingApiModel}
     * @memberof NewScanTaskApiModel
     */
    oAuth2SettingModel?: OAuth2SettingApiModel;
    /**
     * Defines whether a pci scan task going to be started.
     * @type {boolean}
     * @memberof NewScanTaskApiModel
     */
    enablePciScanTask?: boolean;
    /**
     * 
     * @type {BusinessLogicRecorderSettingModel}
     * @memberof NewScanTaskApiModel
     */
    businessLogicRecorderSetting?: BusinessLogicRecorderSettingModel;
    /**
     * Gets or sets the tags
     * @type {Array<string>}
     * @memberof NewScanTaskApiModel
     */
    tags?: Array<string>;
    /**
     * Gets or sets the Comments
     * @type {string}
     * @memberof NewScanTaskApiModel
     */
    comments?: string;
}


/**
 * @export
 */
export const NewScanTaskApiModelCreateTypeEnum = {
    Website: 'Website',
    WebsiteGroup: 'WebsiteGroup'
} as const;
export type NewScanTaskApiModelCreateTypeEnum = typeof NewScanTaskApiModelCreateTypeEnum[keyof typeof NewScanTaskApiModelCreateTypeEnum];

/**
 * @export
 */
export const NewScanTaskApiModelDisallowedHttpMethodsEnum = {
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
export type NewScanTaskApiModelDisallowedHttpMethodsEnum = typeof NewScanTaskApiModelDisallowedHttpMethodsEnum[keyof typeof NewScanTaskApiModelDisallowedHttpMethodsEnum];

/**
 * @export
 */
export const NewScanTaskApiModelAuthenticationProfileOptionEnum = {
    DontUse: 'DontUse',
    UseMatchedProfile: 'UseMatchedProfile',
    SelectedProfile: 'SelectedProfile'
} as const;
export type NewScanTaskApiModelAuthenticationProfileOptionEnum = typeof NewScanTaskApiModelAuthenticationProfileOptionEnum[keyof typeof NewScanTaskApiModelAuthenticationProfileOptionEnum];

/**
 * @export
 */
export const NewScanTaskApiModelScopeEnum = {
    EnteredPathAndBelow: 'EnteredPathAndBelow',
    OnlyEnteredUrl: 'OnlyEnteredUrl',
    WholeDomain: 'WholeDomain'
} as const;
export type NewScanTaskApiModelScopeEnum = typeof NewScanTaskApiModelScopeEnum[keyof typeof NewScanTaskApiModelScopeEnum];

/**
 * @export
 */
export const NewScanTaskApiModelUrlRewriteModeEnum = {
    None: 'None',
    Heuristic: 'Heuristic',
    Custom: 'Custom'
} as const;
export type NewScanTaskApiModelUrlRewriteModeEnum = typeof NewScanTaskApiModelUrlRewriteModeEnum[keyof typeof NewScanTaskApiModelUrlRewriteModeEnum];


/**
 * Check if a given object implements the NewScanTaskApiModel interface.
 */
export function instanceOfNewScanTaskApiModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function NewScanTaskApiModelFromJSON(json: any): NewScanTaskApiModel {
    return NewScanTaskApiModelFromJSONTyped(json, false);
}

export function NewScanTaskApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): NewScanTaskApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'targetUri': !exists(json, 'TargetUri') ? undefined : json['TargetUri'],
        'isTargetUrlRequired': !exists(json, 'IsTargetUrlRequired') ? undefined : json['IsTargetUrlRequired'],
        'createType': !exists(json, 'CreateType') ? undefined : json['CreateType'],
        'websiteGroupId': !exists(json, 'WebsiteGroupId') ? undefined : json['WebsiteGroupId'],
        'additionalWebsites': !exists(json, 'AdditionalWebsites') ? undefined : ((json['AdditionalWebsites'] as Array<any>).map(AdditionalWebsiteModelFromJSON)),
        'basicAuthenticationApiModel': !exists(json, 'BasicAuthenticationApiModel') ? undefined : BasicAuthenticationSettingModelFromJSON(json['BasicAuthenticationApiModel']),
        'clientCertificateAuthenticationSetting': !exists(json, 'ClientCertificateAuthenticationSetting') ? undefined : ClientCertificateAuthenticationApiModelFromJSON(json['ClientCertificateAuthenticationSetting']),
        'cookies': !exists(json, 'Cookies') ? undefined : json['Cookies'],
        'crawlAndAttack': !exists(json, 'CrawlAndAttack') ? undefined : json['CrawlAndAttack'],
        'enableHeuristicChecksInCustomUrlRewrite': !exists(json, 'EnableHeuristicChecksInCustomUrlRewrite') ? undefined : json['EnableHeuristicChecksInCustomUrlRewrite'],
        'excludedLinks': !exists(json, 'ExcludedLinks') ? undefined : ((json['ExcludedLinks'] as Array<any>).map(ExcludedLinkModelFromJSON)),
        'excludedUsageTrackers': !exists(json, 'ExcludedUsageTrackers') ? undefined : ((json['ExcludedUsageTrackers'] as Array<any>).map(ExcludedUsageTrackerModelFromJSON)),
        'disallowedHttpMethods': !exists(json, 'DisallowedHttpMethods') ? undefined : json['DisallowedHttpMethods'],
        'excludeLinks': !exists(json, 'ExcludeLinks') ? undefined : json['ExcludeLinks'],
        'excludeAuthenticationPages': !exists(json, 'ExcludeAuthenticationPages') ? undefined : json['ExcludeAuthenticationPages'],
        'findAndFollowNewLinks': !exists(json, 'FindAndFollowNewLinks') ? undefined : json['FindAndFollowNewLinks'],
        'formAuthenticationSettingModel': !exists(json, 'FormAuthenticationSettingModel') ? undefined : FormAuthenticationSettingModelFromJSON(json['FormAuthenticationSettingModel']),
        'headerAuthentication': !exists(json, 'HeaderAuthentication') ? undefined : HeaderAuthenticationModelFromJSON(json['HeaderAuthentication']),
        'sharkSetting': !exists(json, 'SharkSetting') ? undefined : SharkModelFromJSON(json['SharkSetting']),
        'authenticationProfileOption': !exists(json, 'AuthenticationProfileOption') ? undefined : json['AuthenticationProfileOption'],
        'authenticationProfileId': !exists(json, 'AuthenticationProfileId') ? undefined : json['AuthenticationProfileId'],
        'importedLinks': !exists(json, 'ImportedLinks') ? undefined : json['ImportedLinks'],
        'importedFiles': !exists(json, 'ImportedFiles') ? undefined : ((json['ImportedFiles'] as Array<any>).map(ApiFileModelFromJSON)),
        'isMaxScanDurationEnabled': !exists(json, 'IsMaxScanDurationEnabled') ? undefined : json['IsMaxScanDurationEnabled'],
        'maxDynamicSignatures': !exists(json, 'MaxDynamicSignatures') ? undefined : json['MaxDynamicSignatures'],
        'maxScanDuration': !exists(json, 'MaxScanDuration') ? undefined : json['MaxScanDuration'],
        'policyId': !exists(json, 'PolicyId') ? undefined : json['PolicyId'],
        'reportPolicyId': !exists(json, 'ReportPolicyId') ? undefined : json['ReportPolicyId'],
        'scope': !exists(json, 'Scope') ? undefined : json['Scope'],
        'subPathMaxDynamicSignatures': !exists(json, 'SubPathMaxDynamicSignatures') ? undefined : json['SubPathMaxDynamicSignatures'],
        'timeWindow': !exists(json, 'TimeWindow') ? undefined : ScanTimeWindowModelFromJSON(json['TimeWindow']),
        'urlRewriteAnalyzableExtensions': !exists(json, 'UrlRewriteAnalyzableExtensions') ? undefined : json['UrlRewriteAnalyzableExtensions'],
        'urlRewriteBlockSeparators': !exists(json, 'UrlRewriteBlockSeparators') ? undefined : json['UrlRewriteBlockSeparators'],
        'urlRewriteMode': !exists(json, 'UrlRewriteMode') ? undefined : json['UrlRewriteMode'],
        'urlRewriteRules': !exists(json, 'UrlRewriteRules') ? undefined : ((json['UrlRewriteRules'] as Array<any>).map(UrlRewriteRuleModelFromJSON)),
        'preRequestScriptSetting': !exists(json, 'PreRequestScriptSetting') ? undefined : PreRequestScriptSettingModelFromJSON(json['PreRequestScriptSetting']),
        'doNotDifferentiateProtocols': !exists(json, 'DoNotDifferentiateProtocols') ? undefined : json['DoNotDifferentiateProtocols'],
        'urlRewriteExcludedLinks': !exists(json, 'UrlRewriteExcludedLinks') ? undefined : ((json['UrlRewriteExcludedLinks'] as Array<any>).map(UrlRewriteExcludedPathModelFromJSON)),
        'oAuth2SettingModel': !exists(json, 'OAuth2SettingModel') ? undefined : OAuth2SettingApiModelFromJSON(json['OAuth2SettingModel']),
        'enablePciScanTask': !exists(json, 'EnablePciScanTask') ? undefined : json['EnablePciScanTask'],
        'businessLogicRecorderSetting': !exists(json, 'BusinessLogicRecorderSetting') ? undefined : BusinessLogicRecorderSettingModelFromJSON(json['BusinessLogicRecorderSetting']),
        'tags': !exists(json, 'Tags') ? undefined : json['Tags'],
        'comments': !exists(json, 'Comments') ? undefined : json['Comments'],
    };
}

export function NewScanTaskApiModelToJSON(value?: NewScanTaskApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'TargetUri': value.targetUri,
        'CreateType': value.createType,
        'WebsiteGroupId': value.websiteGroupId,
        'AdditionalWebsites': value.additionalWebsites === undefined ? undefined : ((value.additionalWebsites as Array<any>).map(AdditionalWebsiteModelToJSON)),
        'BasicAuthenticationApiModel': BasicAuthenticationSettingModelToJSON(value.basicAuthenticationApiModel),
        'ClientCertificateAuthenticationSetting': ClientCertificateAuthenticationApiModelToJSON(value.clientCertificateAuthenticationSetting),
        'Cookies': value.cookies,
        'CrawlAndAttack': value.crawlAndAttack,
        'EnableHeuristicChecksInCustomUrlRewrite': value.enableHeuristicChecksInCustomUrlRewrite,
        'ExcludedLinks': value.excludedLinks === undefined ? undefined : ((value.excludedLinks as Array<any>).map(ExcludedLinkModelToJSON)),
        'ExcludedUsageTrackers': value.excludedUsageTrackers === undefined ? undefined : ((value.excludedUsageTrackers as Array<any>).map(ExcludedUsageTrackerModelToJSON)),
        'DisallowedHttpMethods': value.disallowedHttpMethods,
        'ExcludeLinks': value.excludeLinks,
        'ExcludeAuthenticationPages': value.excludeAuthenticationPages,
        'FindAndFollowNewLinks': value.findAndFollowNewLinks,
        'FormAuthenticationSettingModel': FormAuthenticationSettingModelToJSON(value.formAuthenticationSettingModel),
        'HeaderAuthentication': HeaderAuthenticationModelToJSON(value.headerAuthentication),
        'SharkSetting': SharkModelToJSON(value.sharkSetting),
        'AuthenticationProfileOption': value.authenticationProfileOption,
        'AuthenticationProfileId': value.authenticationProfileId,
        'ImportedLinks': value.importedLinks,
        'ImportedFiles': value.importedFiles === undefined ? undefined : ((value.importedFiles as Array<any>).map(ApiFileModelToJSON)),
        'IsMaxScanDurationEnabled': value.isMaxScanDurationEnabled,
        'MaxDynamicSignatures': value.maxDynamicSignatures,
        'MaxScanDuration': value.maxScanDuration,
        'PolicyId': value.policyId,
        'ReportPolicyId': value.reportPolicyId,
        'Scope': value.scope,
        'SubPathMaxDynamicSignatures': value.subPathMaxDynamicSignatures,
        'TimeWindow': ScanTimeWindowModelToJSON(value.timeWindow),
        'UrlRewriteAnalyzableExtensions': value.urlRewriteAnalyzableExtensions,
        'UrlRewriteBlockSeparators': value.urlRewriteBlockSeparators,
        'UrlRewriteMode': value.urlRewriteMode,
        'UrlRewriteRules': value.urlRewriteRules === undefined ? undefined : ((value.urlRewriteRules as Array<any>).map(UrlRewriteRuleModelToJSON)),
        'PreRequestScriptSetting': PreRequestScriptSettingModelToJSON(value.preRequestScriptSetting),
        'DoNotDifferentiateProtocols': value.doNotDifferentiateProtocols,
        'UrlRewriteExcludedLinks': value.urlRewriteExcludedLinks === undefined ? undefined : ((value.urlRewriteExcludedLinks as Array<any>).map(UrlRewriteExcludedPathModelToJSON)),
        'OAuth2SettingModel': OAuth2SettingApiModelToJSON(value.oAuth2SettingModel),
        'EnablePciScanTask': value.enablePciScanTask,
        'BusinessLogicRecorderSetting': BusinessLogicRecorderSettingModelToJSON(value.businessLogicRecorderSetting),
        'Tags': value.tags,
        'Comments': value.comments,
    };
}
