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
exports.BasicAuthenticationCredentialApiModelToJSON = exports.BasicAuthenticationCredentialApiModelFromJSONTyped = exports.BasicAuthenticationCredentialApiModelFromJSON = exports.instanceOfBasicAuthenticationCredentialApiModel = exports.BasicAuthenticationCredentialApiModelAuthenticationTypeEnum = void 0;
/**
 * @export
 */
exports.BasicAuthenticationCredentialApiModelAuthenticationTypeEnum = {
    Basic: 'Basic',
    Ntlm: 'Ntlm',
    Kerberos: 'Kerberos',
    Digest: 'Digest',
    Negotiate: 'Negotiate'
};
/**
 * Check if a given object implements the BasicAuthenticationCredentialApiModel interface.
 */
function instanceOfBasicAuthenticationCredentialApiModel(value) {
    return true;
}
exports.instanceOfBasicAuthenticationCredentialApiModel = instanceOfBasicAuthenticationCredentialApiModel;
function BasicAuthenticationCredentialApiModelFromJSON(json) {
    return BasicAuthenticationCredentialApiModelFromJSONTyped(json, false);
}
exports.BasicAuthenticationCredentialApiModelFromJSON = BasicAuthenticationCredentialApiModelFromJSON;
function BasicAuthenticationCredentialApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'authenticationType': json['AuthenticationType'] == null ? undefined : json['AuthenticationType'],
        'domain': json['Domain'] == null ? undefined : json['Domain'],
        'password': json['Password'] == null ? undefined : json['Password'],
        'uriPrefix': json['UriPrefix'] == null ? undefined : json['UriPrefix'],
        'userName': json['UserName'] == null ? undefined : json['UserName'],
    };
}
exports.BasicAuthenticationCredentialApiModelFromJSONTyped = BasicAuthenticationCredentialApiModelFromJSONTyped;
function BasicAuthenticationCredentialApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'AuthenticationType': value['authenticationType'],
        'Domain': value['domain'],
        'Password': value['password'],
        'UriPrefix': value['uriPrefix'],
        'UserName': value['userName'],
    };
}
exports.BasicAuthenticationCredentialApiModelToJSON = BasicAuthenticationCredentialApiModelToJSON;
//# sourceMappingURL=BasicAuthenticationCredentialApiModel.js.map