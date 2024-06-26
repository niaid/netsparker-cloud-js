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
import type { SslTlsSettingModel } from './SslTlsSettingModel';
import type { Custom404SettingModel } from './Custom404SettingModel';
import type { BruteForceSettingModel } from './BruteForceSettingModel';
import type { CrawlingSettingModel } from './CrawlingSettingModel';
import type { JavaScriptSettingsModel } from './JavaScriptSettingsModel';
import type { SensitiveKeywordSettingModel } from './SensitiveKeywordSettingModel';
import type { AutoCompleteSettingModel } from './AutoCompleteSettingModel';
import type { FormValueSettingModel } from './FormValueSettingModel';
import type { IgnorePatternSettingModel } from './IgnorePatternSettingModel';
import type { SecurityCheckGroupParentModel } from './SecurityCheckGroupParentModel';
import type { CustomHttpHeaderSetting } from './CustomHttpHeaderSetting';
import type { CsrfSettingModel } from './CsrfSettingModel';
import type { ExtensionSettingModel } from './ExtensionSettingModel';
import type { EmailPatternSetting } from './EmailPatternSetting';
import type { AttackingSettingModel } from './AttackingSettingModel';
import type { HttpRequestSettingModel } from './HttpRequestSettingModel';
import type { ProxySettingsModel } from './ProxySettingsModel';
import type { BrowserSetting } from './BrowserSetting';
import type { ScopeSettingModel } from './ScopeSettingModel';
import type { WebStorageSetting } from './WebStorageSetting';
/**
 * Represents a model for carrying out update scan policy settings.
 * @export
 * @interface UpdateScanPolicySettingModel
 */
export interface UpdateScanPolicySettingModel {
    /**
     * Gets or sets the identifier.
     * @type {string}
     * @memberof UpdateScanPolicySettingModel
     */
    id: string;
    /**
     * Gets or sets a value indicating whether this scan policy is shared.
     * @type {boolean}
     * @memberof UpdateScanPolicySettingModel
     */
    isShared?: boolean;
    /**
     * Gets or sets a value indicating whether this scan policy updating via Api.
     * @type {boolean}
     * @memberof UpdateScanPolicySettingModel
     */
    fromApi?: boolean;
    /**
     * Gets the desktop identifier.
     * @type {string}
     * @memberof UpdateScanPolicySettingModel
     */
    desktopId?: string;
    /**
     *
     * @type {AttackingSettingModel}
     * @memberof UpdateScanPolicySettingModel
     */
    attackingSettings: AttackingSettingModel;
    /**
     * Gets or sets the auto complete settings.
     * @type {Array<AutoCompleteSettingModel>}
     * @memberof UpdateScanPolicySettingModel
     */
    autoCompleteSettings?: Array<AutoCompleteSettingModel>;
    /**
     *
     * @type {BruteForceSettingModel}
     * @memberof UpdateScanPolicySettingModel
     */
    bruteForceSettings: BruteForceSettingModel;
    /**
     *
     * @type {CrawlingSettingModel}
     * @memberof UpdateScanPolicySettingModel
     */
    crawlingSettings: CrawlingSettingModel;
    /**
     *
     * @type {CsrfSettingModel}
     * @memberof UpdateScanPolicySettingModel
     */
    csrfSettings?: CsrfSettingModel;
    /**
     *
     * @type {Custom404SettingModel}
     * @memberof UpdateScanPolicySettingModel
     */
    custom404Settings: Custom404SettingModel;
    /**
     * Gets or sets the custom HTTP header settings.
     * @type {Array<CustomHttpHeaderSetting>}
     * @memberof UpdateScanPolicySettingModel
     */
    customHttpHeaderSettings?: Array<CustomHttpHeaderSetting>;
    /**
     * Gets or sets the description.
     * @type {string}
     * @memberof UpdateScanPolicySettingModel
     */
    description?: string;
    /**
     * Gets or sets a value indicating whether knowledgebase is enabled.
     * @type {boolean}
     * @memberof UpdateScanPolicySettingModel
     */
    enableKnowledgebase?: boolean;
    /**
     * Gets or sets the form value settings.
     * @type {Array<FormValueSettingModel>}
     * @memberof UpdateScanPolicySettingModel
     */
    formValueSettings?: Array<FormValueSettingModel>;
    /**
     *
     * @type {HttpRequestSettingModel}
     * @memberof UpdateScanPolicySettingModel
     */
    httpRequestSettings: HttpRequestSettingModel;
    /**
     * Gets or sets the ignored email patterns.
     * @type {Array<EmailPatternSetting>}
     * @memberof UpdateScanPolicySettingModel
     */
    ignoredEmailPatterns?: Array<EmailPatternSetting>;
    /**
     * Gets or sets the ignored parameter patterns.
     * @type {Array<IgnorePatternSettingModel>}
     * @memberof UpdateScanPolicySettingModel
     */
    ignorePatternSettings?: Array<IgnorePatternSettingModel>;
    /**
     *
     * @type {JavaScriptSettingsModel}
     * @memberof UpdateScanPolicySettingModel
     */
    javaScriptSettings: JavaScriptSettingsModel;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof UpdateScanPolicySettingModel
     */
    name: string;
    /**
     *
     * @type {ProxySettingsModel}
     * @memberof UpdateScanPolicySettingModel
     */
    proxySettings?: ProxySettingsModel;
    /**
     *
     * @type {ScopeSettingModel}
     * @memberof UpdateScanPolicySettingModel
     */
    scopeSettings: ScopeSettingModel;
    /**
     * Gets or sets the engine settings.
     * @type {Array<SecurityCheckGroupParentModel>}
     * @memberof UpdateScanPolicySettingModel
     */
    securityCheckGroupParents?: Array<SecurityCheckGroupParentModel>;
    /**
     * Gets or sets the selected website groups.
     * @type {Array<string>}
     * @memberof UpdateScanPolicySettingModel
     */
    selectedGroups?: Array<string>;
    /**
     * Gets or sets the sensitive keyword settings.
     * @type {Array<SensitiveKeywordSettingModel>}
     * @memberof UpdateScanPolicySettingModel
     */
    sensitiveKeywordSettings?: Array<SensitiveKeywordSettingModel>;
    /**
     *
     * @type {SslTlsSettingModel}
     * @memberof UpdateScanPolicySettingModel
     */
    sslTlsSettingModel: SslTlsSettingModel;
    /**
     * Gets or sets the Web Storage Settings
     * @type {Array<WebStorageSetting>}
     * @memberof UpdateScanPolicySettingModel
     */
    webStorageSettings?: Array<WebStorageSetting>;
    /**
     * Gets or sets the Extension Settings
     * @type {Array<ExtensionSettingModel>}
     * @memberof UpdateScanPolicySettingModel
     */
    extensionSettings?: Array<ExtensionSettingModel>;
    /**
     * Gets or sets the default browser parameters
     * @type {Array<BrowserSetting>}
     * @memberof UpdateScanPolicySettingModel
     */
    defaultBrowserParameters?: Array<BrowserSetting>;
    /**
     * Gets or sets the handful browser parameters
     * @type {Array<BrowserSetting>}
     * @memberof UpdateScanPolicySettingModel
     */
    headfulBrowserParameters?: Array<BrowserSetting>;
    /**
     * Gets or sets the resource finders.
     * @type {Array<string>}
     * @memberof UpdateScanPolicySettingModel
     */
    resourceFinders?: Array<string>;
    /**
     * Gets or sets the cloned scan polic setting identifier.
     * @type {string}
     * @memberof UpdateScanPolicySettingModel
     */
    clonedScanPolicySettingId?: string;
}
/**
 * Check if a given object implements the UpdateScanPolicySettingModel interface.
 */
export declare function instanceOfUpdateScanPolicySettingModel(value: object): boolean;
export declare function UpdateScanPolicySettingModelFromJSON(json: any): UpdateScanPolicySettingModel;
export declare function UpdateScanPolicySettingModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateScanPolicySettingModel;
export declare function UpdateScanPolicySettingModelToJSON(value?: UpdateScanPolicySettingModel | null): any;
