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
const NameValuePair_1 = require("./NameValuePair");
const OAuth2SettingEndpoint_1 = require("./OAuth2SettingEndpoint");
const ResponseFields_1 = require("./ResponseFields");
const BasicAuthenticationSettingApiModel_1 = require("./BasicAuthenticationSettingApiModel");
const ThreeLeggedFields_1 = require("./ThreeLeggedFields");
const FormAuthenticationSettingApiModel_1 = require("./FormAuthenticationSettingApiModel");
/**
 * @export
 */
exports.OAuth2SettingApiModelFlowTypeEnum = {
    AuthorizationCode: 'AuthorizationCode',
    Implicit: 'Implicit',
    ResourceOwnerPasswordCredentials: 'ResourceOwnerPasswordCredentials',
    ClientCredentials: 'ClientCredentials',
    Custom: 'Custom'
};
/**
 * @export
 */
exports.OAuth2SettingApiModelAuthenticationTypeEnum = {
    None: 'None',
    Form: 'Form',
    Basic: 'Basic'
};
/**
 * Check if a given object implements the OAuth2SettingApiModel interface.
 */
function instanceOfOAuth2SettingApiModel(value) {
    return true;
}
exports.instanceOfOAuth2SettingApiModel = instanceOfOAuth2SettingApiModel;
function OAuth2SettingApiModelFromJSON(json) {
    return OAuth2SettingApiModelFromJSONTyped(json, false);
}
exports.OAuth2SettingApiModelFromJSON = OAuth2SettingApiModelFromJSON;
function OAuth2SettingApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'serializedPolicyData': json['SerializedPolicyData'] == null ? undefined : json['SerializedPolicyData'],
        'flowType': json['FlowType'] == null ? undefined : json['FlowType'],
        'authenticationType': json['AuthenticationType'] == null ? undefined : json['AuthenticationType'],
        'accessTokenEndpoint': json['AccessTokenEndpoint'] == null ? undefined : (0, OAuth2SettingEndpoint_1.OAuth2SettingEndpointFromJSON)(json['AccessTokenEndpoint']),
        'authorizationCodeEndpoint': json['AuthorizationCodeEndpoint'] == null ? undefined : (0, OAuth2SettingEndpoint_1.OAuth2SettingEndpointFromJSON)(json['AuthorizationCodeEndpoint']),
        'accessTokenItems': json['AccessTokenItems'] == null ? undefined : (json['AccessTokenItems'].map(NameValuePair_1.NameValuePairFromJSON)),
        'authorizationCodeItems': json['AuthorizationCodeItems'] == null ? undefined : (json['AuthorizationCodeItems'].map(NameValuePair_1.NameValuePairFromJSON)),
        'responseFields': json['ResponseFields'] == null ? undefined : (0, ResponseFields_1.ResponseFieldsFromJSON)(json['ResponseFields']),
        'threeLeggedFields': json['ThreeLeggedFields'] == null ? undefined : (0, ThreeLeggedFields_1.ThreeLeggedFieldsFromJSON)(json['ThreeLeggedFields']),
        'id': json['Id'] == null ? undefined : json['Id'],
        'enabled': json['Enabled'] == null ? undefined : json['Enabled'],
        'headers': json['Headers'] == null ? undefined : (json['Headers'].map(NameValuePair_1.NameValuePairFromJSON)),
        'formAuthenticationSetting': json['FormAuthenticationSetting'] == null ? undefined : (0, FormAuthenticationSettingApiModel_1.FormAuthenticationSettingApiModelFromJSON)(json['FormAuthenticationSetting']),
        'basicAuthenticationSetting': json['BasicAuthenticationSetting'] == null ? undefined : (0, BasicAuthenticationSettingApiModel_1.BasicAuthenticationSettingApiModelFromJSON)(json['BasicAuthenticationSetting']),
    };
}
exports.OAuth2SettingApiModelFromJSONTyped = OAuth2SettingApiModelFromJSONTyped;
function OAuth2SettingApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'SerializedPolicyData': value['serializedPolicyData'],
        'FlowType': value['flowType'],
        'AuthenticationType': value['authenticationType'],
        'AccessTokenEndpoint': (0, OAuth2SettingEndpoint_1.OAuth2SettingEndpointToJSON)(value['accessTokenEndpoint']),
        'AuthorizationCodeEndpoint': (0, OAuth2SettingEndpoint_1.OAuth2SettingEndpointToJSON)(value['authorizationCodeEndpoint']),
        'AccessTokenItems': value['accessTokenItems'] == null ? undefined : (value['accessTokenItems'].map(NameValuePair_1.NameValuePairToJSON)),
        'AuthorizationCodeItems': value['authorizationCodeItems'] == null ? undefined : (value['authorizationCodeItems'].map(NameValuePair_1.NameValuePairToJSON)),
        'ResponseFields': (0, ResponseFields_1.ResponseFieldsToJSON)(value['responseFields']),
        'ThreeLeggedFields': (0, ThreeLeggedFields_1.ThreeLeggedFieldsToJSON)(value['threeLeggedFields']),
        'Id': value['id'],
        'Enabled': value['enabled'],
        'Headers': value['headers'] == null ? undefined : (value['headers'].map(NameValuePair_1.NameValuePairToJSON)),
        'FormAuthenticationSetting': (0, FormAuthenticationSettingApiModel_1.FormAuthenticationSettingApiModelToJSON)(value['formAuthenticationSetting']),
        'BasicAuthenticationSetting': (0, BasicAuthenticationSettingApiModel_1.BasicAuthenticationSettingApiModelToJSON)(value['basicAuthenticationSetting']),
    };
}
exports.OAuth2SettingApiModelToJSON = OAuth2SettingApiModelToJSON;
//# sourceMappingURL=OAuth2SettingApiModel.js.map