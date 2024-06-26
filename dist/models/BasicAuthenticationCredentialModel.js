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
exports.BasicAuthenticationCredentialModelToJSON = exports.BasicAuthenticationCredentialModelFromJSONTyped = exports.BasicAuthenticationCredentialModelFromJSON = exports.instanceOfBasicAuthenticationCredentialModel = exports.BasicAuthenticationCredentialModelAuthenticationTypeEnum = void 0;
/**
 * @export
 */
exports.BasicAuthenticationCredentialModelAuthenticationTypeEnum = {
    Basic: 'Basic',
    Ntlm: 'Ntlm',
    Kerberos: 'Kerberos',
    Digest: 'Digest',
    Negotiate: 'Negotiate'
};
/**
 * Check if a given object implements the BasicAuthenticationCredentialModel interface.
 */
function instanceOfBasicAuthenticationCredentialModel(value) {
    if (!('password' in value))
        return false;
    if (!('uriPrefix' in value))
        return false;
    if (!('userName' in value))
        return false;
    return true;
}
exports.instanceOfBasicAuthenticationCredentialModel = instanceOfBasicAuthenticationCredentialModel;
function BasicAuthenticationCredentialModelFromJSON(json) {
    return BasicAuthenticationCredentialModelFromJSONTyped(json, false);
}
exports.BasicAuthenticationCredentialModelFromJSON = BasicAuthenticationCredentialModelFromJSON;
function BasicAuthenticationCredentialModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'authenticationType': json['AuthenticationType'] == null ? undefined : json['AuthenticationType'],
        'domain': json['Domain'] == null ? undefined : json['Domain'],
        'password': json['Password'],
        'uriPrefix': json['UriPrefix'],
        'userName': json['UserName'],
        'originalUriPrefix': json['OriginalUriPrefix'] == null ? undefined : json['OriginalUriPrefix'],
        'originalUserName': json['OriginalUserName'] == null ? undefined : json['OriginalUserName'],
        'originalPassword': json['OriginalPassword'] == null ? undefined : json['OriginalPassword'],
        'isReplacedCredentials': json['IsReplacedCredentials'] == null ? undefined : json['IsReplacedCredentials'],
    };
}
exports.BasicAuthenticationCredentialModelFromJSONTyped = BasicAuthenticationCredentialModelFromJSONTyped;
function BasicAuthenticationCredentialModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'AuthenticationType': value['authenticationType'],
        'Domain': value['domain'],
        'Password': value['password'],
        'UriPrefix': value['uriPrefix'],
        'UserName': value['userName'],
        'OriginalUriPrefix': value['originalUriPrefix'],
        'OriginalUserName': value['originalUserName'],
        'OriginalPassword': value['originalPassword'],
        'IsReplacedCredentials': value['isReplacedCredentials'],
    };
}
exports.BasicAuthenticationCredentialModelToJSON = BasicAuthenticationCredentialModelToJSON;
//# sourceMappingURL=BasicAuthenticationCredentialModel.js.map