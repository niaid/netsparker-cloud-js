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
exports.FormAuthenticationSettingApiModel = void 0;
/**
* Provides credentials for form authentication.
*/
class FormAuthenticationSettingApiModel {
    static getAttributeTypeMap() {
        return FormAuthenticationSettingApiModel.attributeTypeMap;
    }
}
exports.FormAuthenticationSettingApiModel = FormAuthenticationSettingApiModel;
FormAuthenticationSettingApiModel.discriminator = undefined;
FormAuthenticationSettingApiModel.attributeTypeMap = [
    {
        "name": "customScripts",
        "baseName": "CustomScripts",
        "type": "Array<FormAuthenticationCustomScript>"
    },
    {
        "name": "detectBearerToken",
        "baseName": "DetectBearerToken",
        "type": "boolean"
    },
    {
        "name": "detectAuthorizationTokens",
        "baseName": "DetectAuthorizationTokens",
        "type": "boolean"
    },
    {
        "name": "disableLogoutDetection",
        "baseName": "DisableLogoutDetection",
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
        "type": "string"
    },
    {
        "name": "logoutRedirectPattern",
        "baseName": "LogoutRedirectPattern",
        "type": "string"
    },
    {
        "name": "overrideTargetUrlWithAuthenticatedPage",
        "baseName": "OverrideTargetUrlWithAuthenticatedPage",
        "type": "boolean"
    },
    {
        "name": "password",
        "baseName": "Password",
        "type": "string"
    },
    {
        "name": "userName",
        "baseName": "UserName",
        "type": "string"
    },
    {
        "name": "formAuthType",
        "baseName": "FormAuthType",
        "type": "FormAuthenticationSettingApiModel.FormAuthTypeEnum"
    },
    {
        "name": "otpSettings",
        "baseName": "OtpSettings",
        "type": "OtpSettings"
    },
    {
        "name": "hashicorpVaultSetting",
        "baseName": "HashicorpVaultSetting",
        "type": "FormAuthenticationHashicorpVaultSetting"
    },
    {
        "name": "cyberArkVaultSetting",
        "baseName": "CyberArkVaultSetting",
        "type": "FormAuthenticationCyberArkVaultSetting"
    }
];
(function (FormAuthenticationSettingApiModel) {
    let FormAuthTypeEnum;
    (function (FormAuthTypeEnum) {
        FormAuthTypeEnum[FormAuthTypeEnum["Manual"] = 'Manual'] = "Manual";
        FormAuthTypeEnum[FormAuthTypeEnum["Integration"] = 'Integration'] = "Integration";
    })(FormAuthTypeEnum = FormAuthenticationSettingApiModel.FormAuthTypeEnum || (FormAuthenticationSettingApiModel.FormAuthTypeEnum = {}));
})(FormAuthenticationSettingApiModel = exports.FormAuthenticationSettingApiModel || (exports.FormAuthenticationSettingApiModel = {}));
//# sourceMappingURL=formAuthenticationSettingApiModel.js.map