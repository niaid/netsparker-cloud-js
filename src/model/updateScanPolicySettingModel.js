"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.UpdateScanPolicySettingModel = void 0;
/**
* Represents a model for carrying out update scan policy settings.
*/
class UpdateScanPolicySettingModel {
    static getAttributeTypeMap() {
        return UpdateScanPolicySettingModel.attributeTypeMap;
    }
}
exports.UpdateScanPolicySettingModel = UpdateScanPolicySettingModel;
UpdateScanPolicySettingModel.discriminator = undefined;
UpdateScanPolicySettingModel.attributeTypeMap = [
    {
        "name": "id",
        "baseName": "Id",
        "type": "string"
    },
    {
        "name": "isShared",
        "baseName": "IsShared",
        "type": "boolean"
    },
    {
        "name": "desktopId",
        "baseName": "DesktopId",
        "type": "string"
    },
    {
        "name": "attackingSettings",
        "baseName": "AttackingSettings",
        "type": "AttackingSettingModel"
    },
    {
        "name": "autoCompleteSettings",
        "baseName": "AutoCompleteSettings",
        "type": "Array<AutoCompleteSettingModel>"
    },
    {
        "name": "bruteForceSettings",
        "baseName": "BruteForceSettings",
        "type": "BruteForceSettingModel"
    },
    {
        "name": "crawlingSettings",
        "baseName": "CrawlingSettings",
        "type": "CrawlingSettingModel"
    },
    {
        "name": "csrfSettings",
        "baseName": "CsrfSettings",
        "type": "CsrfSettingModel"
    },
    {
        "name": "custom404Settings",
        "baseName": "Custom404Settings",
        "type": "Custom404SettingModel"
    },
    {
        "name": "customHttpHeaderSettings",
        "baseName": "CustomHttpHeaderSettings",
        "type": "Array<CustomHttpHeaderSetting>"
    },
    {
        "name": "description",
        "baseName": "Description",
        "type": "string"
    },
    {
        "name": "enableKnowledgebase",
        "baseName": "EnableKnowledgebase",
        "type": "boolean"
    },
    {
        "name": "formValueSettings",
        "baseName": "FormValueSettings",
        "type": "Array<FormValueSettingModel>"
    },
    {
        "name": "httpRequestSettings",
        "baseName": "HttpRequestSettings",
        "type": "HttpRequestSettingModel"
    },
    {
        "name": "ignoredEmailPatterns",
        "baseName": "IgnoredEmailPatterns",
        "type": "Array<EmailPatternSetting>"
    },
    {
        "name": "ignorePatternSettings",
        "baseName": "IgnorePatternSettings",
        "type": "Array<IgnorePatternSettingModel>"
    },
    {
        "name": "javaScriptSettings",
        "baseName": "JavaScriptSettings",
        "type": "JavaScriptSettingsModel"
    },
    {
        "name": "name",
        "baseName": "Name",
        "type": "string"
    },
    {
        "name": "proxySettings",
        "baseName": "ProxySettings",
        "type": "ProxySettingsModel"
    },
    {
        "name": "scopeSettings",
        "baseName": "ScopeSettings",
        "type": "ScopeSettingModel"
    },
    {
        "name": "securityCheckGroupParents",
        "baseName": "SecurityCheckGroupParents",
        "type": "Array<SecurityCheckGroupParentModel>"
    },
    {
        "name": "selectedGroups",
        "baseName": "SelectedGroups",
        "type": "Array<string>"
    },
    {
        "name": "sensitiveKeywordSettings",
        "baseName": "SensitiveKeywordSettings",
        "type": "Array<SensitiveKeywordSettingModel>"
    },
    {
        "name": "sslTlsSettingModel",
        "baseName": "SslTlsSettingModel",
        "type": "SslTlsSettingModel"
    },
    {
        "name": "webStorageSettings",
        "baseName": "WebStorageSettings",
        "type": "Array<WebStorageSetting>"
    },
    {
        "name": "extensionSettings",
        "baseName": "ExtensionSettings",
        "type": "Array<ExtensionSettingModel>"
    },
    {
        "name": "resourceFinders",
        "baseName": "ResourceFinders",
        "type": "Array<string>"
    },
    {
        "name": "clonedScanPolicySettingId",
        "baseName": "ClonedScanPolicySettingId",
        "type": "string"
    }
];
//# sourceMappingURL=updateScanPolicySettingModel.js.map