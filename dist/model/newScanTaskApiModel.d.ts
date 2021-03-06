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
import { AdditionalWebsiteModel } from './additionalWebsiteModel';
import { ApiFileModel } from './apiFileModel';
import { BasicAuthenticationSettingModel } from './basicAuthenticationSettingModel';
import { ClientCertificateAuthenticationApiModel } from './clientCertificateAuthenticationApiModel';
import { ExcludedLinkModel } from './excludedLinkModel';
import { ExcludedUsageTrackerModel } from './excludedUsageTrackerModel';
import { FormAuthenticationSettingModel } from './formAuthenticationSettingModel';
import { HeaderAuthenticationModel } from './headerAuthenticationModel';
import { OAuth2SettingApiModel } from './oAuth2SettingApiModel';
import { PreRequestScriptSettingModel } from './preRequestScriptSettingModel';
import { ScanTimeWindowModel } from './scanTimeWindowModel';
import { SharkModel } from './sharkModel';
import { UrlRewriteExcludedPathModel } from './urlRewriteExcludedPathModel';
import { UrlRewriteRuleModel } from './urlRewriteRuleModel';
/**
* Contains properties that required to start scan.
*/
export declare class NewScanTaskApiModel {
    /**
    * Gets or sets the target URI.
    */
    'targetUri': string;
    /**
    * Gets or sets the additional websites to scan.
    */
    'additionalWebsites'?: Array<AdditionalWebsiteModel>;
    'basicAuthenticationApiModel'?: BasicAuthenticationSettingModel;
    'clientCertificateAuthenticationSetting'?: ClientCertificateAuthenticationApiModel;
    /**
    * Gets or sets the cookies. Separate multiple cookies with semicolon. Cookie values must be URL encoded. You can use the  following format: Cookiename=Value
    */
    'cookies'?: string;
    /**
    * Gets or sets a value indicating whether parallel attacker is enabled.  Default: true
    */
    'crawlAndAttack'?: boolean;
    /**
    * Gets or sets a value indicating whether Heuristic URL Rewrite support is enabled together with custom URL Rewrite  support.
    */
    'enableHeuristicChecksInCustomUrlRewrite'?: boolean;
    /**
    * Gets or sets the excluded links.  Default: \"(log|sign)\\\\-?(out|off)\", \"exit\", \"endsession\", \"gtm\\\\.js\"
    */
    'excludedLinks'?: Array<ExcludedLinkModel>;
    /**
    * Gets or sets the excluded usage trackers.
    */
    'excludedUsageTrackers'?: Array<ExcludedUsageTrackerModel>;
    /**
    * Gets or sets the disallowed http methods.
    */
    'disallowedHttpMethods'?: Array<NewScanTaskApiModel.DisallowedHttpMethodsEnum>;
    /**
    * Gets or sets a value indicating whether links should be excluded/included.  Default: <see ref=\"bool.True\" />
    */
    'excludeLinks'?: boolean;
    /**
    * Specifies whether the authentication related pages like login, logout etc. should be excluded from the scan.  If form authentication is enabled, exclude authentication pages will be set as true. If you want to scan exclude authentication pages please set as false.
    */
    'excludeAuthenticationPages'?: boolean;
    /**
    * Gets or sets a value indicating whether automatic crawling is enabled.
    */
    'findAndFollowNewLinks'?: boolean;
    'formAuthenticationSettingModel'?: FormAuthenticationSettingModel;
    'headerAuthentication'?: HeaderAuthenticationModel;
    'sharkSetting'?: SharkModel;
    /**
    * Gets or sets the type of the authentication profile option.
    */
    'authenticationProfileOption'?: NewScanTaskApiModel.AuthenticationProfileOptionEnum;
    /**
    * Gets or sets the type of the authentication profile identifier.
    */
    'authenticationProfileId'?: string;
    /**
    * Gets or sets the imported links.
    */
    'importedLinks'?: Array<string>;
    /**
    * Gets or sets the imported files. If imported files have not contains any URL, the file not added to scan profile.
    */
    'importedFiles'?: Array<ApiFileModel>;
    /**
    * Gets or sets a value indicating whether max scan duration is enabled.  This is only used for scheduled group scan and regular group scan.
    */
    'isMaxScanDurationEnabled'?: boolean;
    /**
    * Gets or sets the root path maximum dynamic signatures for heuristic URL Rewrite detection.  Default: 60
    */
    'maxDynamicSignatures'?: number;
    /**
    * Gets or sets the maximum duration of the scan in hours.  Default: 48 hours
    */
    'maxScanDuration'?: number;
    /**
    * Gets or sets the scan policy identifier.  Default: Default Security Checks
    */
    'policyId'?: string;
    /**
    * Gets or sets the report policy identifier.  Default: Default Report Policy
    */
    'reportPolicyId'?: string;
    /**
    * Gets or sets the scan scope.  Default: {Invicti.Cloud.Core.Models.ScanTaskScope.EnteredPathAndBelow}
    */
    'scope'?: NewScanTaskApiModel.ScopeEnum;
    /**
    * Gets or sets the sub path maximum dynamic signatures for heuristic URL Rewrite detection.  Default: 30
    */
    'subPathMaxDynamicSignatures'?: number;
    'timeWindow'?: ScanTimeWindowModel;
    /**
    * Gets or sets the extensions that will be analyzed for heuristic URL Rewrite detection.  Default: htm,html
    */
    'urlRewriteAnalyzableExtensions'?: string;
    /**
    * Gets or sets the block separators for heuristic URL Rewrite detection.  Default: /_ $.,;|:
    */
    'urlRewriteBlockSeparators'?: string;
    /**
    * Gets or sets the URL Rewrite mode.  Default: Heuristic
    */
    'urlRewriteMode'?: NewScanTaskApiModel.UrlRewriteModeEnum;
    /**
    * Gets or sets the URL Rewrite rules.
    */
    'urlRewriteRules'?: Array<UrlRewriteRuleModel>;
    'preRequestScriptSetting'?: PreRequestScriptSettingModel;
    /**
    * Gets or sets a value indicating whether http and https protocols are differentiated.
    */
    'doNotDifferentiateProtocols'?: boolean;
    /**
    * Gets or sets the URL rewrite excluded links.
    */
    'urlRewriteExcludedLinks'?: Array<UrlRewriteExcludedPathModel>;
    'oAuth2SettingModel'?: OAuth2SettingApiModel;
    /**
    * Defines whether a pci scan task going to be started.
    */
    'enablePciScanTask'?: boolean;
    static discriminator: string | undefined;
    static attributeTypeMap: Array<{
        name: string;
        baseName: string;
        type: string;
    }>;
    static getAttributeTypeMap(): {
        name: string;
        baseName: string;
        type: string;
    }[];
}
export declare namespace NewScanTaskApiModel {
    enum DisallowedHttpMethodsEnum {
        Get,
        Post,
        Connect,
        Head,
        Trace,
        Debug,
        Track,
        Put,
        Options,
        Delete,
        Link,
        Unlink,
        Patch
    }
    enum AuthenticationProfileOptionEnum {
        DontUse,
        UseMatchedProfile,
        SelectedProfile
    }
    enum ScopeEnum {
        EnteredPathAndBelow,
        OnlyEnteredUrl,
        WholeDomain
    }
    enum UrlRewriteModeEnum {
        None,
        Heuristic,
        Custom
    }
}
