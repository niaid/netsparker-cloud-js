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
exports.BasicAuthenticationSettingApiModelToJSON = exports.BasicAuthenticationSettingApiModelFromJSONTyped = exports.BasicAuthenticationSettingApiModelFromJSON = exports.instanceOfBasicAuthenticationSettingApiModel = void 0;
const runtime_1 = require("../runtime");
const BasicAuthenticationCredentialApiModel_1 = require("./BasicAuthenticationCredentialApiModel");
/**
 * Check if a given object implements the BasicAuthenticationSettingApiModel interface.
 */
function instanceOfBasicAuthenticationSettingApiModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfBasicAuthenticationSettingApiModel = instanceOfBasicAuthenticationSettingApiModel;
function BasicAuthenticationSettingApiModelFromJSON(json) {
    return BasicAuthenticationSettingApiModelFromJSONTyped(json, false);
}
exports.BasicAuthenticationSettingApiModelFromJSON = BasicAuthenticationSettingApiModelFromJSON;
function BasicAuthenticationSettingApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'alwaysAuthenticateNoChallenge': !(0, runtime_1.exists)(json, 'AlwaysAuthenticateNoChallenge') ? undefined : json['AlwaysAuthenticateNoChallenge'],
        'credentials': !(0, runtime_1.exists)(json, 'Credentials') ? undefined : (json['Credentials'].map(BasicAuthenticationCredentialApiModel_1.BasicAuthenticationCredentialApiModelFromJSON)),
    };
}
exports.BasicAuthenticationSettingApiModelFromJSONTyped = BasicAuthenticationSettingApiModelFromJSONTyped;
function BasicAuthenticationSettingApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AlwaysAuthenticateNoChallenge': value.alwaysAuthenticateNoChallenge,
        'Credentials': value.credentials === undefined ? undefined : (value.credentials.map(BasicAuthenticationCredentialApiModel_1.BasicAuthenticationCredentialApiModelToJSON)),
    };
}
exports.BasicAuthenticationSettingApiModelToJSON = BasicAuthenticationSettingApiModelToJSON;
//# sourceMappingURL=BasicAuthenticationSettingApiModel.js.map