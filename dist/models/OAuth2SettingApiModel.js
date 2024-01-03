"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.OAuth2SettingApiModelToJSON = exports.OAuth2SettingApiModelFromJSONTyped = exports.OAuth2SettingApiModelFromJSON = exports.instanceOfOAuth2SettingApiModel = exports.OAuth2SettingApiModelAuthenticationTypeEnum = exports.OAuth2SettingApiModelFlowTypeEnum = void 0;
const runtime_1 = require("../runtime");
const BasicAuthenticationSettingApiModel_1 = require("./BasicAuthenticationSettingApiModel");
const FormAuthenticationSettingApiModel_1 = require("./FormAuthenticationSettingApiModel");
const NameValuePair_1 = require("./NameValuePair");
const OAuth2SettingEndpoint_1 = require("./OAuth2SettingEndpoint");
const ResponseFields_1 = require("./ResponseFields");
const ThreeLeggedFields_1 = require("./ThreeLeggedFields");
/**
* @export
* @enum {string}
*/
var OAuth2SettingApiModelFlowTypeEnum;
(function (OAuth2SettingApiModelFlowTypeEnum) {
    OAuth2SettingApiModelFlowTypeEnum["AuthorizationCode"] = "AuthorizationCode";
    OAuth2SettingApiModelFlowTypeEnum["Implicit"] = "Implicit";
    OAuth2SettingApiModelFlowTypeEnum["ResourceOwnerPasswordCredentials"] = "ResourceOwnerPasswordCredentials";
    OAuth2SettingApiModelFlowTypeEnum["ClientCredentials"] = "ClientCredentials";
    OAuth2SettingApiModelFlowTypeEnum["Custom"] = "Custom";
})(OAuth2SettingApiModelFlowTypeEnum = exports.OAuth2SettingApiModelFlowTypeEnum || (exports.OAuth2SettingApiModelFlowTypeEnum = {}));
/**
* @export
* @enum {string}
*/
var OAuth2SettingApiModelAuthenticationTypeEnum;
(function (OAuth2SettingApiModelAuthenticationTypeEnum) {
    OAuth2SettingApiModelAuthenticationTypeEnum["None"] = "None";
    OAuth2SettingApiModelAuthenticationTypeEnum["Form"] = "Form";
    OAuth2SettingApiModelAuthenticationTypeEnum["Basic"] = "Basic";
})(OAuth2SettingApiModelAuthenticationTypeEnum = exports.OAuth2SettingApiModelAuthenticationTypeEnum || (exports.OAuth2SettingApiModelAuthenticationTypeEnum = {}));
/**
 * Check if a given object implements the OAuth2SettingApiModel interface.
 */
function instanceOfOAuth2SettingApiModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfOAuth2SettingApiModel = instanceOfOAuth2SettingApiModel;
function OAuth2SettingApiModelFromJSON(json) {
    return OAuth2SettingApiModelFromJSONTyped(json, false);
}
exports.OAuth2SettingApiModelFromJSON = OAuth2SettingApiModelFromJSON;
function OAuth2SettingApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'serializedPolicyData': !(0, runtime_1.exists)(json, 'SerializedPolicyData') ? undefined : json['SerializedPolicyData'],
        'flowType': !(0, runtime_1.exists)(json, 'FlowType') ? undefined : json['FlowType'],
        'authenticationType': !(0, runtime_1.exists)(json, 'AuthenticationType') ? undefined : json['AuthenticationType'],
        'accessTokenEndpoint': !(0, runtime_1.exists)(json, 'AccessTokenEndpoint') ? undefined : (0, OAuth2SettingEndpoint_1.OAuth2SettingEndpointFromJSON)(json['AccessTokenEndpoint']),
        'authorizationCodeEndpoint': !(0, runtime_1.exists)(json, 'AuthorizationCodeEndpoint') ? undefined : (0, OAuth2SettingEndpoint_1.OAuth2SettingEndpointFromJSON)(json['AuthorizationCodeEndpoint']),
        'accessTokenItems': !(0, runtime_1.exists)(json, 'AccessTokenItems') ? undefined : (json['AccessTokenItems'].map(NameValuePair_1.NameValuePairFromJSON)),
        'authorizationCodeItems': !(0, runtime_1.exists)(json, 'AuthorizationCodeItems') ? undefined : (json['AuthorizationCodeItems'].map(NameValuePair_1.NameValuePairFromJSON)),
        'responseFields': !(0, runtime_1.exists)(json, 'ResponseFields') ? undefined : (0, ResponseFields_1.ResponseFieldsFromJSON)(json['ResponseFields']),
        'threeLeggedFields': !(0, runtime_1.exists)(json, 'ThreeLeggedFields') ? undefined : (0, ThreeLeggedFields_1.ThreeLeggedFieldsFromJSON)(json['ThreeLeggedFields']),
        'id': !(0, runtime_1.exists)(json, 'Id') ? undefined : json['Id'],
        'enabled': !(0, runtime_1.exists)(json, 'Enabled') ? undefined : json['Enabled'],
        'headers': !(0, runtime_1.exists)(json, 'Headers') ? undefined : (json['Headers'].map(NameValuePair_1.NameValuePairFromJSON)),
        'formAuthenticationSetting': !(0, runtime_1.exists)(json, 'FormAuthenticationSetting') ? undefined : (0, FormAuthenticationSettingApiModel_1.FormAuthenticationSettingApiModelFromJSON)(json['FormAuthenticationSetting']),
        'basicAuthenticationSetting': !(0, runtime_1.exists)(json, 'BasicAuthenticationSetting') ? undefined : (0, BasicAuthenticationSettingApiModel_1.BasicAuthenticationSettingApiModelFromJSON)(json['BasicAuthenticationSetting']),
    };
}
exports.OAuth2SettingApiModelFromJSONTyped = OAuth2SettingApiModelFromJSONTyped;
function OAuth2SettingApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'SerializedPolicyData': value.serializedPolicyData,
        'FlowType': value.flowType,
        'AuthenticationType': value.authenticationType,
        'AccessTokenEndpoint': (0, OAuth2SettingEndpoint_1.OAuth2SettingEndpointToJSON)(value.accessTokenEndpoint),
        'AuthorizationCodeEndpoint': (0, OAuth2SettingEndpoint_1.OAuth2SettingEndpointToJSON)(value.authorizationCodeEndpoint),
        'AccessTokenItems': value.accessTokenItems === undefined ? undefined : (value.accessTokenItems.map(NameValuePair_1.NameValuePairToJSON)),
        'AuthorizationCodeItems': value.authorizationCodeItems === undefined ? undefined : (value.authorizationCodeItems.map(NameValuePair_1.NameValuePairToJSON)),
        'ResponseFields': (0, ResponseFields_1.ResponseFieldsToJSON)(value.responseFields),
        'ThreeLeggedFields': (0, ThreeLeggedFields_1.ThreeLeggedFieldsToJSON)(value.threeLeggedFields),
        'Id': value.id,
        'Enabled': value.enabled,
        'Headers': value.headers === undefined ? undefined : (value.headers.map(NameValuePair_1.NameValuePairToJSON)),
        'FormAuthenticationSetting': (0, FormAuthenticationSettingApiModel_1.FormAuthenticationSettingApiModelToJSON)(value.formAuthenticationSetting),
        'BasicAuthenticationSetting': (0, BasicAuthenticationSettingApiModel_1.BasicAuthenticationSettingApiModelToJSON)(value.basicAuthenticationSetting),
    };
}
exports.OAuth2SettingApiModelToJSON = OAuth2SettingApiModelToJSON;
//# sourceMappingURL=OAuth2SettingApiModel.js.map