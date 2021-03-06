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
exports.FormAuthenticationSettingModel = void 0;
/**
* Represents a model for carrying out form authentication settings.
*/
class FormAuthenticationSettingModel {
    static getAttributeTypeMap() {
        return FormAuthenticationSettingModel.attributeTypeMap;
    }
}
exports.FormAuthenticationSettingModel = FormAuthenticationSettingModel;
FormAuthenticationSettingModel.discriminator = undefined;
FormAuthenticationSettingModel.attributeTypeMap = [
    {
        "name": "integrations",
        "baseName": "Integrations",
        "type": "{ [key: string]: ScanNotificationIntegrationViewModel; }"
    },
    {
        "name": "customScripts",
        "baseName": "CustomScripts",
        "type": "Array<FormAuthenticationCustomScript>"
    },
    {
        "name": "interactiveLoginRequired",
        "baseName": "InteractiveLoginRequired",
        "type": "boolean"
    },
    {
        "name": "defaultPersonaValidation",
        "baseName": "DefaultPersonaValidation",
        "type": "boolean"
    },
    {
        "name": "detectBearerToken",
        "baseName": "DetectBearerToken",
        "type": "boolean"
    },
    {
        "name": "disableLogoutDetection",
        "baseName": "DisableLogoutDetection",
        "type": "boolean"
    },
    {
        "name": "isEnabled",
        "baseName": "IsEnabled",
        "type": "boolean"
    },
    {
        "name": "loginFormUrl",
        "baseName": "LoginFormUrl",
        "type": "string"
    },
    {
        "name": "loginRequiredUrl",
        "baseName": "LoginRequiredUrl",
        "type": "string"
    },
    {
        "name": "logoutKeywordPatterns",
        "baseName": "LogoutKeywordPatterns",
        "type": "Array<LogoutKeywordPatternModel>"
    },
    {
        "name": "logoutKeywordPatternsValue",
        "baseName": "LogoutKeywordPatternsValue",
        "type": "string"
    },
    {
        "name": "logoutRedirectPattern",
        "baseName": "LogoutRedirectPattern",
        "type": "string"
    },
    {
        "name": "overrideTargetUrl",
        "baseName": "OverrideTargetUrl",
        "type": "boolean"
    },
    {
        "name": "personas",
        "baseName": "Personas",
        "type": "Array<FormAuthenticationPersona>"
    },
    {
        "name": "personasValidation",
        "baseName": "PersonasValidation",
        "type": "boolean"
    }
];
//# sourceMappingURL=formAuthenticationSettingModel.js.map