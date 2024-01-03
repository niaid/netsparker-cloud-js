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
const runtime_1 = require("../runtime");
/**
* @export
* @enum {string}
*/
var BasicAuthenticationCredentialModelAuthenticationTypeEnum;
(function (BasicAuthenticationCredentialModelAuthenticationTypeEnum) {
    BasicAuthenticationCredentialModelAuthenticationTypeEnum["Basic"] = "Basic";
    BasicAuthenticationCredentialModelAuthenticationTypeEnum["Ntlm"] = "Ntlm";
    BasicAuthenticationCredentialModelAuthenticationTypeEnum["Kerberos"] = "Kerberos";
    BasicAuthenticationCredentialModelAuthenticationTypeEnum["Digest"] = "Digest";
    BasicAuthenticationCredentialModelAuthenticationTypeEnum["Negotiate"] = "Negotiate";
})(BasicAuthenticationCredentialModelAuthenticationTypeEnum = exports.BasicAuthenticationCredentialModelAuthenticationTypeEnum || (exports.BasicAuthenticationCredentialModelAuthenticationTypeEnum = {}));
/**
 * Check if a given object implements the BasicAuthenticationCredentialModel interface.
 */
function instanceOfBasicAuthenticationCredentialModel(value) {
    let isInstance = true;
    isInstance = isInstance && "password" in value;
    isInstance = isInstance && "uriPrefix" in value;
    isInstance = isInstance && "userName" in value;
    return isInstance;
}
exports.instanceOfBasicAuthenticationCredentialModel = instanceOfBasicAuthenticationCredentialModel;
function BasicAuthenticationCredentialModelFromJSON(json) {
    return BasicAuthenticationCredentialModelFromJSONTyped(json, false);
}
exports.BasicAuthenticationCredentialModelFromJSON = BasicAuthenticationCredentialModelFromJSON;
function BasicAuthenticationCredentialModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'authenticationType': !(0, runtime_1.exists)(json, 'AuthenticationType') ? undefined : json['AuthenticationType'],
        'domain': !(0, runtime_1.exists)(json, 'Domain') ? undefined : json['Domain'],
        'password': json['Password'],
        'uriPrefix': json['UriPrefix'],
        'userName': json['UserName'],
        'originalUriPrefix': !(0, runtime_1.exists)(json, 'OriginalUriPrefix') ? undefined : json['OriginalUriPrefix'],
        'originalUserName': !(0, runtime_1.exists)(json, 'OriginalUserName') ? undefined : json['OriginalUserName'],
        'originalPassword': !(0, runtime_1.exists)(json, 'OriginalPassword') ? undefined : json['OriginalPassword'],
        'isReplacedCredentials': !(0, runtime_1.exists)(json, 'IsReplacedCredentials') ? undefined : json['IsReplacedCredentials'],
    };
}
exports.BasicAuthenticationCredentialModelFromJSONTyped = BasicAuthenticationCredentialModelFromJSONTyped;
function BasicAuthenticationCredentialModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AuthenticationType': value.authenticationType,
        'Domain': value.domain,
        'Password': value.password,
        'UriPrefix': value.uriPrefix,
        'UserName': value.userName,
        'OriginalUriPrefix': value.originalUriPrefix,
        'OriginalUserName': value.originalUserName,
        'OriginalPassword': value.originalPassword,
        'IsReplacedCredentials': value.isReplacedCredentials,
    };
}
exports.BasicAuthenticationCredentialModelToJSON = BasicAuthenticationCredentialModelToJSON;
//# sourceMappingURL=BasicAuthenticationCredentialModel.js.map