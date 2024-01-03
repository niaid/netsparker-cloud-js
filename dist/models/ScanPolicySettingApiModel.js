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
import { exists } from '../runtime';
import { AttackingSettingModelFromJSON, AttackingSettingModelToJSON, } from './AttackingSettingModel';
import { AutoCompleteSettingModelFromJSON, AutoCompleteSettingModelToJSON, } from './AutoCompleteSettingModel';
import { BrowserSettingFromJSON, BrowserSettingToJSON, } from './BrowserSetting';
import { BruteForceSettingModelFromJSON, BruteForceSettingModelToJSON, } from './BruteForceSettingModel';
import { CrawlingSettingModelFromJSON, CrawlingSettingModelToJSON, } from './CrawlingSettingModel';
import { CsrfSettingModelFromJSON, CsrfSettingModelToJSON, } from './CsrfSettingModel';
import { Custom404SettingModelFromJSON, Custom404SettingModelToJSON, } from './Custom404SettingModel';
import { CustomHttpHeaderSettingFromJSON, CustomHttpHeaderSettingToJSON, } from './CustomHttpHeaderSetting';
import { EmailPatternSettingFromJSON, EmailPatternSettingToJSON, } from './EmailPatternSetting';
import { ExtensionSettingModelFromJSON, ExtensionSettingModelToJSON, } from './ExtensionSettingModel';
import { FormValueSettingModelFromJSON, FormValueSettingModelToJSON, } from './FormValueSettingModel';
import { HttpRequestSettingModelFromJSON, HttpRequestSettingModelToJSON, } from './HttpRequestSettingModel';
import { IgnorePatternSettingModelFromJSON, IgnorePatternSettingModelToJSON, } from './IgnorePatternSettingModel';
import { JavaScriptSettingsModelFromJSON, JavaScriptSettingsModelToJSON, } from './JavaScriptSettingsModel';
import { ProxySettingsModelFromJSON, ProxySettingsModelToJSON, } from './ProxySettingsModel';
import { ScopeSettingModelFromJSON, ScopeSettingModelToJSON, } from './ScopeSettingModel';
import { SecurityCheckGroupParentModelFromJSON, SecurityCheckGroupParentModelToJSON, } from './SecurityCheckGroupParentModel';
import { SensitiveKeywordSettingModelFromJSON, SensitiveKeywordSettingModelToJSON, } from './SensitiveKeywordSettingModel';
import { SslTlsSettingModelFromJSON, SslTlsSettingModelToJSON, } from './SslTlsSettingModel';
import { WebStorageSettingFromJSON, WebStorageSettingToJSON, } from './WebStorageSetting';
/**
 * Check if a given object implements the ScanPolicySettingApiModel interface.
 */
export function instanceOfScanPolicySettingApiModel(value) {
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
export function ScanPolicySettingApiModelFromJSON(json) {
    return ScanPolicySettingApiModelFromJSONTyped(json, false);
}
export function ScanPolicySettingApiModelFromJSONTyped(json, ignoreDiscriminator) {
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
        'autoCompleteSettings': !exists(json, 'AutoCompleteSettings') ? undefined : (json['AutoCompleteSettings'].map(AutoCompleteSettingModelFromJSON)),
        'bruteForceSettings': BruteForceSettingModelFromJSON(json['BruteForceSettings']),
        'crawlingSettings': CrawlingSettingModelFromJSON(json['CrawlingSettings']),
        'csrfSettings': !exists(json, 'CsrfSettings') ? undefined : CsrfSettingModelFromJSON(json['CsrfSettings']),
        'custom404Settings': Custom404SettingModelFromJSON(json['Custom404Settings']),
        'customHttpHeaderSettings': !exists(json, 'CustomHttpHeaderSettings') ? undefined : (json['CustomHttpHeaderSettings'].map(CustomHttpHeaderSettingFromJSON)),
        'description': !exists(json, 'Description') ? undefined : json['Description'],
        'enableKnowledgebase': !exists(json, 'EnableKnowledgebase') ? undefined : json['EnableKnowledgebase'],
        'formValueSettings': !exists(json, 'FormValueSettings') ? undefined : (json['FormValueSettings'].map(FormValueSettingModelFromJSON)),
        'httpRequestSettings': HttpRequestSettingModelFromJSON(json['HttpRequestSettings']),
        'ignoredEmailPatterns': !exists(json, 'IgnoredEmailPatterns') ? undefined : (json['IgnoredEmailPatterns'].map(EmailPatternSettingFromJSON)),
        'ignorePatternSettings': !exists(json, 'IgnorePatternSettings') ? undefined : (json['IgnorePatternSettings'].map(IgnorePatternSettingModelFromJSON)),
        'javaScriptSettings': JavaScriptSettingsModelFromJSON(json['JavaScriptSettings']),
        'name': json['Name'],
        'proxySettings': !exists(json, 'ProxySettings') ? undefined : ProxySettingsModelFromJSON(json['ProxySettings']),
        'scopeSettings': ScopeSettingModelFromJSON(json['ScopeSettings']),
        'securityCheckGroupParents': !exists(json, 'SecurityCheckGroupParents') ? undefined : (json['SecurityCheckGroupParents'].map(SecurityCheckGroupParentModelFromJSON)),
        'selectedGroups': !exists(json, 'SelectedGroups') ? undefined : json['SelectedGroups'],
        'sensitiveKeywordSettings': !exists(json, 'SensitiveKeywordSettings') ? undefined : (json['SensitiveKeywordSettings'].map(SensitiveKeywordSettingModelFromJSON)),
        'sslTlsSettingModel': SslTlsSettingModelFromJSON(json['SslTlsSettingModel']),
        'webStorageSettings': !exists(json, 'WebStorageSettings') ? undefined : (json['WebStorageSettings'].map(WebStorageSettingFromJSON)),
        'extensionSettings': !exists(json, 'ExtensionSettings') ? undefined : (json['ExtensionSettings'].map(ExtensionSettingModelFromJSON)),
        'defaultBrowserParameters': !exists(json, 'DefaultBrowserParameters') ? undefined : (json['DefaultBrowserParameters'].map(BrowserSettingFromJSON)),
        'headfulBrowserParameters': !exists(json, 'HeadfulBrowserParameters') ? undefined : (json['HeadfulBrowserParameters'].map(BrowserSettingFromJSON)),
        'resourceFinders': !exists(json, 'ResourceFinders') ? undefined : json['ResourceFinders'],
        'clonedScanPolicySettingId': !exists(json, 'ClonedScanPolicySettingId') ? undefined : json['ClonedScanPolicySettingId'],
    };
}
export function ScanPolicySettingApiModelToJSON(value) {
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
        'AutoCompleteSettings': value.autoCompleteSettings === undefined ? undefined : (value.autoCompleteSettings.map(AutoCompleteSettingModelToJSON)),
        'BruteForceSettings': BruteForceSettingModelToJSON(value.bruteForceSettings),
        'CrawlingSettings': CrawlingSettingModelToJSON(value.crawlingSettings),
        'CsrfSettings': CsrfSettingModelToJSON(value.csrfSettings),
        'Custom404Settings': Custom404SettingModelToJSON(value.custom404Settings),
        'CustomHttpHeaderSettings': value.customHttpHeaderSettings === undefined ? undefined : (value.customHttpHeaderSettings.map(CustomHttpHeaderSettingToJSON)),
        'Description': value.description,
        'EnableKnowledgebase': value.enableKnowledgebase,
        'FormValueSettings': value.formValueSettings === undefined ? undefined : (value.formValueSettings.map(FormValueSettingModelToJSON)),
        'HttpRequestSettings': HttpRequestSettingModelToJSON(value.httpRequestSettings),
        'IgnoredEmailPatterns': value.ignoredEmailPatterns === undefined ? undefined : (value.ignoredEmailPatterns.map(EmailPatternSettingToJSON)),
        'IgnorePatternSettings': value.ignorePatternSettings === undefined ? undefined : (value.ignorePatternSettings.map(IgnorePatternSettingModelToJSON)),
        'JavaScriptSettings': JavaScriptSettingsModelToJSON(value.javaScriptSettings),
        'Name': value.name,
        'ProxySettings': ProxySettingsModelToJSON(value.proxySettings),
        'ScopeSettings': ScopeSettingModelToJSON(value.scopeSettings),
        'SecurityCheckGroupParents': value.securityCheckGroupParents === undefined ? undefined : (value.securityCheckGroupParents.map(SecurityCheckGroupParentModelToJSON)),
        'SelectedGroups': value.selectedGroups,
        'SensitiveKeywordSettings': value.sensitiveKeywordSettings === undefined ? undefined : (value.sensitiveKeywordSettings.map(SensitiveKeywordSettingModelToJSON)),
        'SslTlsSettingModel': SslTlsSettingModelToJSON(value.sslTlsSettingModel),
        'WebStorageSettings': value.webStorageSettings === undefined ? undefined : (value.webStorageSettings.map(WebStorageSettingToJSON)),
        'ExtensionSettings': value.extensionSettings === undefined ? undefined : (value.extensionSettings.map(ExtensionSettingModelToJSON)),
        'DefaultBrowserParameters': value.defaultBrowserParameters === undefined ? undefined : (value.defaultBrowserParameters.map(BrowserSettingToJSON)),
        'HeadfulBrowserParameters': value.headfulBrowserParameters === undefined ? undefined : (value.headfulBrowserParameters.map(BrowserSettingToJSON)),
        'ResourceFinders': value.resourceFinders,
        'ClonedScanPolicySettingId': value.clonedScanPolicySettingId,
    };
}
//# sourceMappingURL=ScanPolicySettingApiModel.js.map