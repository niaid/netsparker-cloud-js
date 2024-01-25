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
import type { AttackingSettingModel } from './AttackingSettingModel';
import {
    AttackingSettingModelFromJSON,
    AttackingSettingModelFromJSONTyped,
    AttackingSettingModelToJSON,
} from './AttackingSettingModel';
import type { AutoCompleteSettingModel } from './AutoCompleteSettingModel';
import {
    AutoCompleteSettingModelFromJSON,
    AutoCompleteSettingModelFromJSONTyped,
    AutoCompleteSettingModelToJSON,
} from './AutoCompleteSettingModel';
import type { BrowserSetting } from './BrowserSetting';
import {
    BrowserSettingFromJSON,
    BrowserSettingFromJSONTyped,
    BrowserSettingToJSON,
} from './BrowserSetting';
import type { BruteForceSettingModel } from './BruteForceSettingModel';
import {
    BruteForceSettingModelFromJSON,
    BruteForceSettingModelFromJSONTyped,
    BruteForceSettingModelToJSON,
} from './BruteForceSettingModel';
import type { CrawlingSettingModel } from './CrawlingSettingModel';
import {
    CrawlingSettingModelFromJSON,
    CrawlingSettingModelFromJSONTyped,
    CrawlingSettingModelToJSON,
} from './CrawlingSettingModel';
import type { CsrfSettingModel } from './CsrfSettingModel';
import {
    CsrfSettingModelFromJSON,
    CsrfSettingModelFromJSONTyped,
    CsrfSettingModelToJSON,
} from './CsrfSettingModel';
import type { Custom404SettingModel } from './Custom404SettingModel';
import {
    Custom404SettingModelFromJSON,
    Custom404SettingModelFromJSONTyped,
    Custom404SettingModelToJSON,
} from './Custom404SettingModel';
import type { CustomHttpHeaderSetting } from './CustomHttpHeaderSetting';
import {
    CustomHttpHeaderSettingFromJSON,
    CustomHttpHeaderSettingFromJSONTyped,
    CustomHttpHeaderSettingToJSON,
} from './CustomHttpHeaderSetting';
import type { EmailPatternSetting } from './EmailPatternSetting';
import {
    EmailPatternSettingFromJSON,
    EmailPatternSettingFromJSONTyped,
    EmailPatternSettingToJSON,
} from './EmailPatternSetting';
import type { ExtensionSettingModel } from './ExtensionSettingModel';
import {
    ExtensionSettingModelFromJSON,
    ExtensionSettingModelFromJSONTyped,
    ExtensionSettingModelToJSON,
} from './ExtensionSettingModel';
import type { FormValueSettingModel } from './FormValueSettingModel';
import {
    FormValueSettingModelFromJSON,
    FormValueSettingModelFromJSONTyped,
    FormValueSettingModelToJSON,
} from './FormValueSettingModel';
import type { HttpRequestSettingModel } from './HttpRequestSettingModel';
import {
    HttpRequestSettingModelFromJSON,
    HttpRequestSettingModelFromJSONTyped,
    HttpRequestSettingModelToJSON,
} from './HttpRequestSettingModel';
import type { IgnorePatternSettingModel } from './IgnorePatternSettingModel';
import {
    IgnorePatternSettingModelFromJSON,
    IgnorePatternSettingModelFromJSONTyped,
    IgnorePatternSettingModelToJSON,
} from './IgnorePatternSettingModel';
import type { JavaScriptSettingsModel } from './JavaScriptSettingsModel';
import {
    JavaScriptSettingsModelFromJSON,
    JavaScriptSettingsModelFromJSONTyped,
    JavaScriptSettingsModelToJSON,
} from './JavaScriptSettingsModel';
import type { ProxySettingsModel } from './ProxySettingsModel';
import {
    ProxySettingsModelFromJSON,
    ProxySettingsModelFromJSONTyped,
    ProxySettingsModelToJSON,
} from './ProxySettingsModel';
import type { ScopeSettingModel } from './ScopeSettingModel';
import {
    ScopeSettingModelFromJSON,
    ScopeSettingModelFromJSONTyped,
    ScopeSettingModelToJSON,
} from './ScopeSettingModel';
import type { SecurityCheckGroupParentModel } from './SecurityCheckGroupParentModel';
import {
    SecurityCheckGroupParentModelFromJSON,
    SecurityCheckGroupParentModelFromJSONTyped,
    SecurityCheckGroupParentModelToJSON,
} from './SecurityCheckGroupParentModel';
import type { SensitiveKeywordSettingModel } from './SensitiveKeywordSettingModel';
import {
    SensitiveKeywordSettingModelFromJSON,
    SensitiveKeywordSettingModelFromJSONTyped,
    SensitiveKeywordSettingModelToJSON,
} from './SensitiveKeywordSettingModel';
import type { SslTlsSettingModel } from './SslTlsSettingModel';
import {
    SslTlsSettingModelFromJSON,
    SslTlsSettingModelFromJSONTyped,
    SslTlsSettingModelToJSON,
} from './SslTlsSettingModel';
import type { WebStorageSetting } from './WebStorageSetting';
import {
    WebStorageSettingFromJSON,
    WebStorageSettingFromJSONTyped,
    WebStorageSettingToJSON,
} from './WebStorageSetting';

/**
 * Represents a model for carrying out scan policy settings.
 * @export
 * @interface ScanPolicySettingApiModel
 */
export interface ScanPolicySettingApiModel {
    /**
     * Gets or sets a value indicating whether this policy is policy owner account default.
     * @type {boolean}
     * @memberof ScanPolicySettingApiModel
     */
    isAccountDefault?: boolean;
    /**
     * Gets or sets the identifier.
     * @type {string}
     * @memberof ScanPolicySettingApiModel
     */
    id?: string;
    /**
     * Gets or sets a value indicating whether this scan policy is shared.
     * @type {boolean}
     * @memberof ScanPolicySettingApiModel
     */
    isShared?: boolean;
    /**
     * Gets or sets a value indicating whether this scan policy updating via Api.
     * @type {boolean}
     * @memberof ScanPolicySettingApiModel
     */
    fromApi?: boolean;
    /**
     * Gets the desktop identifier.
     * @type {string}
     * @memberof ScanPolicySettingApiModel
     */
    desktopId?: string;
    /**
     * 
     * @type {AttackingSettingModel}
     * @memberof ScanPolicySettingApiModel
     */
    attackingSettings: AttackingSettingModel;
    /**
     * Gets or sets the auto complete settings.
     * @type {Array<AutoCompleteSettingModel>}
     * @memberof ScanPolicySettingApiModel
     */
    autoCompleteSettings?: Array<AutoCompleteSettingModel>;
    /**
     * 
     * @type {BruteForceSettingModel}
     * @memberof ScanPolicySettingApiModel
     */
    bruteForceSettings: BruteForceSettingModel;
    /**
     * 
     * @type {CrawlingSettingModel}
     * @memberof ScanPolicySettingApiModel
     */
    crawlingSettings: CrawlingSettingModel;
    /**
     * 
     * @type {CsrfSettingModel}
     * @memberof ScanPolicySettingApiModel
     */
    csrfSettings?: CsrfSettingModel;
    /**
     * 
     * @type {Custom404SettingModel}
     * @memberof ScanPolicySettingApiModel
     */
    custom404Settings: Custom404SettingModel;
    /**
     * Gets or sets the custom HTTP header settings.
     * @type {Array<CustomHttpHeaderSetting>}
     * @memberof ScanPolicySettingApiModel
     */
    customHttpHeaderSettings?: Array<CustomHttpHeaderSetting>;
    /**
     * Gets or sets the description.
     * @type {string}
     * @memberof ScanPolicySettingApiModel
     */
    description?: string;
    /**
     * Gets or sets a value indicating whether knowledgebase is enabled.
     * @type {boolean}
     * @memberof ScanPolicySettingApiModel
     */
    enableKnowledgebase?: boolean;
    /**
     * Gets or sets the form value settings.
     * @type {Array<FormValueSettingModel>}
     * @memberof ScanPolicySettingApiModel
     */
    formValueSettings?: Array<FormValueSettingModel>;
    /**
     * 
     * @type {HttpRequestSettingModel}
     * @memberof ScanPolicySettingApiModel
     */
    httpRequestSettings: HttpRequestSettingModel;
    /**
     * Gets or sets the ignored email patterns.
     * @type {Array<EmailPatternSetting>}
     * @memberof ScanPolicySettingApiModel
     */
    ignoredEmailPatterns?: Array<EmailPatternSetting>;
    /**
     * Gets or sets the ignored parameter patterns.
     * @type {Array<IgnorePatternSettingModel>}
     * @memberof ScanPolicySettingApiModel
     */
    ignorePatternSettings?: Array<IgnorePatternSettingModel>;
    /**
     * 
     * @type {JavaScriptSettingsModel}
     * @memberof ScanPolicySettingApiModel
     */
    javaScriptSettings: JavaScriptSettingsModel;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof ScanPolicySettingApiModel
     */
    name: string;
    /**
     * 
     * @type {ProxySettingsModel}
     * @memberof ScanPolicySettingApiModel
     */
    proxySettings?: ProxySettingsModel;
    /**
     * 
     * @type {ScopeSettingModel}
     * @memberof ScanPolicySettingApiModel
     */
    scopeSettings: ScopeSettingModel;
    /**
     * Gets or sets the engine settings.
     * @type {Array<SecurityCheckGroupParentModel>}
     * @memberof ScanPolicySettingApiModel
     */
    securityCheckGroupParents?: Array<SecurityCheckGroupParentModel>;
    /**
     * Gets or sets the selected website groups.
     * @type {Array<string>}
     * @memberof ScanPolicySettingApiModel
     */
    selectedGroups?: Array<string>;
    /**
     * Gets or sets the sensitive keyword settings.
     * @type {Array<SensitiveKeywordSettingModel>}
     * @memberof ScanPolicySettingApiModel
     */
    sensitiveKeywordSettings?: Array<SensitiveKeywordSettingModel>;
    /**
     * 
     * @type {SslTlsSettingModel}
     * @memberof ScanPolicySettingApiModel
     */
    sslTlsSettingModel: SslTlsSettingModel;
    /**
     * Gets or sets the Web Storage Settings
     * @type {Array<WebStorageSetting>}
     * @memberof ScanPolicySettingApiModel
     */
    webStorageSettings?: Array<WebStorageSetting>;
    /**
     * Gets or sets the Extension Settings
     * @type {Array<ExtensionSettingModel>}
     * @memberof ScanPolicySettingApiModel
     */
    extensionSettings?: Array<ExtensionSettingModel>;
    /**
     * Gets or sets the default browser parameters
     * @type {Array<BrowserSetting>}
     * @memberof ScanPolicySettingApiModel
     */
    defaultBrowserParameters?: Array<BrowserSetting>;
    /**
     * Gets or sets the handful browser parameters
     * @type {Array<BrowserSetting>}
     * @memberof ScanPolicySettingApiModel
     */
    headfulBrowserParameters?: Array<BrowserSetting>;
    /**
     * Gets or sets the resource finders.
     * @type {Array<string>}
     * @memberof ScanPolicySettingApiModel
     */
    resourceFinders?: Array<string>;
    /**
     * Gets or sets the cloned scan polic setting identifier.
     * @type {string}
     * @memberof ScanPolicySettingApiModel
     */
    clonedScanPolicySettingId?: string;
}

/**
 * Check if a given object implements the ScanPolicySettingApiModel interface.
 */
export function instanceOfScanPolicySettingApiModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "attackingSettings" in value;
    isInstance = isInstance && "bruteForceSettings" in value;
    isInstance = isInstance && "crawlingSettings" in value;
    isInstance = isInstance && "custom404Settings" in value;
    isInstance = isInstance && "httpRequestSettings" in value;
    isInstance = isInstance && "javaScriptSettings" in value;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "scopeSettings" in value;
    isInstance = isInstance && "sslTlsSettingModel" in value;

    return isInstance;
}

export function ScanPolicySettingApiModelFromJSON(json: any): ScanPolicySettingApiModel {
    return ScanPolicySettingApiModelFromJSONTyped(json, false);
}

export function ScanPolicySettingApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanPolicySettingApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'isAccountDefault': !exists(json, 'IsAccountDefault') ? undefined : json['IsAccountDefault'],
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'isShared': !exists(json, 'IsShared') ? undefined : json['IsShared'],
        'fromApi': !exists(json, 'FromApi') ? undefined : json['FromApi'],
        'desktopId': !exists(json, 'DesktopId') ? undefined : json['DesktopId'],
        'attackingSettings': AttackingSettingModelFromJSON(json['AttackingSettings']),
        'autoCompleteSettings': !exists(json, 'AutoCompleteSettings') ? undefined : ((json['AutoCompleteSettings'] as Array<any>).map(AutoCompleteSettingModelFromJSON)),
        'bruteForceSettings': BruteForceSettingModelFromJSON(json['BruteForceSettings']),
        'crawlingSettings': CrawlingSettingModelFromJSON(json['CrawlingSettings']),
        'csrfSettings': !exists(json, 'CsrfSettings') ? undefined : CsrfSettingModelFromJSON(json['CsrfSettings']),
        'custom404Settings': Custom404SettingModelFromJSON(json['Custom404Settings']),
        'customHttpHeaderSettings': !exists(json, 'CustomHttpHeaderSettings') ? undefined : ((json['CustomHttpHeaderSettings'] as Array<any>).map(CustomHttpHeaderSettingFromJSON)),
        'description': !exists(json, 'Description') ? undefined : json['Description'],
        'enableKnowledgebase': !exists(json, 'EnableKnowledgebase') ? undefined : json['EnableKnowledgebase'],
        'formValueSettings': !exists(json, 'FormValueSettings') ? undefined : ((json['FormValueSettings'] as Array<any>).map(FormValueSettingModelFromJSON)),
        'httpRequestSettings': HttpRequestSettingModelFromJSON(json['HttpRequestSettings']),
        'ignoredEmailPatterns': !exists(json, 'IgnoredEmailPatterns') ? undefined : ((json['IgnoredEmailPatterns'] as Array<any>).map(EmailPatternSettingFromJSON)),
        'ignorePatternSettings': !exists(json, 'IgnorePatternSettings') ? undefined : ((json['IgnorePatternSettings'] as Array<any>).map(IgnorePatternSettingModelFromJSON)),
        'javaScriptSettings': JavaScriptSettingsModelFromJSON(json['JavaScriptSettings']),
        'name': json['Name'],
        'proxySettings': !exists(json, 'ProxySettings') ? undefined : ProxySettingsModelFromJSON(json['ProxySettings']),
        'scopeSettings': ScopeSettingModelFromJSON(json['ScopeSettings']),
        'securityCheckGroupParents': !exists(json, 'SecurityCheckGroupParents') ? undefined : ((json['SecurityCheckGroupParents'] as Array<any>).map(SecurityCheckGroupParentModelFromJSON)),
        'selectedGroups': !exists(json, 'SelectedGroups') ? undefined : json['SelectedGroups'],
        'sensitiveKeywordSettings': !exists(json, 'SensitiveKeywordSettings') ? undefined : ((json['SensitiveKeywordSettings'] as Array<any>).map(SensitiveKeywordSettingModelFromJSON)),
        'sslTlsSettingModel': SslTlsSettingModelFromJSON(json['SslTlsSettingModel']),
        'webStorageSettings': !exists(json, 'WebStorageSettings') ? undefined : ((json['WebStorageSettings'] as Array<any>).map(WebStorageSettingFromJSON)),
        'extensionSettings': !exists(json, 'ExtensionSettings') ? undefined : ((json['ExtensionSettings'] as Array<any>).map(ExtensionSettingModelFromJSON)),
        'defaultBrowserParameters': !exists(json, 'DefaultBrowserParameters') ? undefined : ((json['DefaultBrowserParameters'] as Array<any>).map(BrowserSettingFromJSON)),
        'headfulBrowserParameters': !exists(json, 'HeadfulBrowserParameters') ? undefined : ((json['HeadfulBrowserParameters'] as Array<any>).map(BrowserSettingFromJSON)),
        'resourceFinders': !exists(json, 'ResourceFinders') ? undefined : json['ResourceFinders'],
        'clonedScanPolicySettingId': !exists(json, 'ClonedScanPolicySettingId') ? undefined : json['ClonedScanPolicySettingId'],
    };
}

export function ScanPolicySettingApiModelToJSON(value?: ScanPolicySettingApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'IsAccountDefault': value.isAccountDefault,
        'Id': value.id,
        'IsShared': value.isShared,
        'FromApi': value.fromApi,
        'DesktopId': value.desktopId,
        'AttackingSettings': AttackingSettingModelToJSON(value.attackingSettings),
        'AutoCompleteSettings': value.autoCompleteSettings === undefined ? undefined : ((value.autoCompleteSettings as Array<any>).map(AutoCompleteSettingModelToJSON)),
        'BruteForceSettings': BruteForceSettingModelToJSON(value.bruteForceSettings),
        'CrawlingSettings': CrawlingSettingModelToJSON(value.crawlingSettings),
        'CsrfSettings': CsrfSettingModelToJSON(value.csrfSettings),
        'Custom404Settings': Custom404SettingModelToJSON(value.custom404Settings),
        'CustomHttpHeaderSettings': value.customHttpHeaderSettings === undefined ? undefined : ((value.customHttpHeaderSettings as Array<any>).map(CustomHttpHeaderSettingToJSON)),
        'Description': value.description,
        'EnableKnowledgebase': value.enableKnowledgebase,
        'FormValueSettings': value.formValueSettings === undefined ? undefined : ((value.formValueSettings as Array<any>).map(FormValueSettingModelToJSON)),
        'HttpRequestSettings': HttpRequestSettingModelToJSON(value.httpRequestSettings),
        'IgnoredEmailPatterns': value.ignoredEmailPatterns === undefined ? undefined : ((value.ignoredEmailPatterns as Array<any>).map(EmailPatternSettingToJSON)),
        'IgnorePatternSettings': value.ignorePatternSettings === undefined ? undefined : ((value.ignorePatternSettings as Array<any>).map(IgnorePatternSettingModelToJSON)),
        'JavaScriptSettings': JavaScriptSettingsModelToJSON(value.javaScriptSettings),
        'Name': value.name,
        'ProxySettings': ProxySettingsModelToJSON(value.proxySettings),
        'ScopeSettings': ScopeSettingModelToJSON(value.scopeSettings),
        'SecurityCheckGroupParents': value.securityCheckGroupParents === undefined ? undefined : ((value.securityCheckGroupParents as Array<any>).map(SecurityCheckGroupParentModelToJSON)),
        'SelectedGroups': value.selectedGroups,
        'SensitiveKeywordSettings': value.sensitiveKeywordSettings === undefined ? undefined : ((value.sensitiveKeywordSettings as Array<any>).map(SensitiveKeywordSettingModelToJSON)),
        'SslTlsSettingModel': SslTlsSettingModelToJSON(value.sslTlsSettingModel),
        'WebStorageSettings': value.webStorageSettings === undefined ? undefined : ((value.webStorageSettings as Array<any>).map(WebStorageSettingToJSON)),
        'ExtensionSettings': value.extensionSettings === undefined ? undefined : ((value.extensionSettings as Array<any>).map(ExtensionSettingModelToJSON)),
        'DefaultBrowserParameters': value.defaultBrowserParameters === undefined ? undefined : ((value.defaultBrowserParameters as Array<any>).map(BrowserSettingToJSON)),
        'HeadfulBrowserParameters': value.headfulBrowserParameters === undefined ? undefined : ((value.headfulBrowserParameters as Array<any>).map(BrowserSettingToJSON)),
        'ResourceFinders': value.resourceFinders,
        'ClonedScanPolicySettingId': value.clonedScanPolicySettingId,
    };
}

