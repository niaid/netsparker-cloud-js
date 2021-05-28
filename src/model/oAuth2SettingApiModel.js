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
/**
* Provides an inputs for OAuth 2.0 Flow.
*/
class OAuth2SettingApiModel {
    static getAttributeTypeMap() {
        return OAuth2SettingApiModel.attributeTypeMap;
    }
}
OAuth2SettingApiModel.discriminator = undefined;
OAuth2SettingApiModel.attributeTypeMap = [
    {
        "name": "flowType",
        "baseName": "FlowType",
        "type": "OAuth2SettingApiModel.FlowTypeEnum"
    },
    {
        "name": "authenticationType",
        "baseName": "AuthenticationType",
        "type": "OAuth2SettingApiModel.AuthenticationTypeEnum"
    },
    {
        "name": "accessTokenEndpoint",
        "baseName": "AccessTokenEndpoint",
        "type": "OAuth2SettingEndpoint"
    },
    {
        "name": "authorizationCodeEndpoint",
        "baseName": "AuthorizationCodeEndpoint",
        "type": "OAuth2SettingEndpoint"
    },
    {
        "name": "accessTokenItems",
        "baseName": "AccessTokenItems",
        "type": "Array<NameValuePair>"
    },
    {
        "name": "authorizationCodeItems",
        "baseName": "AuthorizationCodeItems",
        "type": "Array<NameValuePair>"
    },
    {
        "name": "responseFields",
        "baseName": "ResponseFields",
        "type": "ResponseFields"
    },
    {
        "name": "threeLeggedFields",
        "baseName": "ThreeLeggedFields",
        "type": "ThreeLeggedFields"
    },
    {
        "name": "id",
        "baseName": "Id",
        "type": "string"
    },
    {
        "name": "headers",
        "baseName": "Headers",
        "type": "Array<NameValuePair>"
    },
    {
        "name": "formAuthenticationSetting",
        "baseName": "FormAuthenticationSetting",
        "type": "FormAuthenticationSettingApiModel"
    },
    {
        "name": "basicAuthenticationSetting",
        "baseName": "BasicAuthenticationSetting",
        "type": "BasicAuthenticationSettingApiModel"
    }
];
exports.OAuth2SettingApiModel = OAuth2SettingApiModel;
(function (OAuth2SettingApiModel) {
    let FlowTypeEnum;
    (function (FlowTypeEnum) {
        FlowTypeEnum[FlowTypeEnum["AuthorizationCode"] = 'AuthorizationCode'] = "AuthorizationCode";
        FlowTypeEnum[FlowTypeEnum["Implicit"] = 'Implicit'] = "Implicit";
        FlowTypeEnum[FlowTypeEnum["ResourceOwnerPasswordCredentials"] = 'ResourceOwnerPasswordCredentials'] = "ResourceOwnerPasswordCredentials";
        FlowTypeEnum[FlowTypeEnum["ClientCredentials"] = 'ClientCredentials'] = "ClientCredentials";
        FlowTypeEnum[FlowTypeEnum["Custom"] = 'Custom'] = "Custom";
    })(FlowTypeEnum = OAuth2SettingApiModel.FlowTypeEnum || (OAuth2SettingApiModel.FlowTypeEnum = {}));
    let AuthenticationTypeEnum;
    (function (AuthenticationTypeEnum) {
        AuthenticationTypeEnum[AuthenticationTypeEnum["None"] = 'None'] = "None";
        AuthenticationTypeEnum[AuthenticationTypeEnum["Form"] = 'Form'] = "Form";
        AuthenticationTypeEnum[AuthenticationTypeEnum["Basic"] = 'Basic'] = "Basic";
    })(AuthenticationTypeEnum = OAuth2SettingApiModel.AuthenticationTypeEnum || (OAuth2SettingApiModel.AuthenticationTypeEnum = {}));
})(OAuth2SettingApiModel = exports.OAuth2SettingApiModel || (exports.OAuth2SettingApiModel = {}));
//# sourceMappingURL=oAuth2SettingApiModel.js.map