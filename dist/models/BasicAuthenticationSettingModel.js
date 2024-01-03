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
exports.BasicAuthenticationSettingModelToJSON = exports.BasicAuthenticationSettingModelFromJSONTyped = exports.BasicAuthenticationSettingModelFromJSON = exports.instanceOfBasicAuthenticationSettingModel = void 0;
const runtime_1 = require("../runtime");
const BasicAuthenticationCredentialModel_1 = require("./BasicAuthenticationCredentialModel");
/**
 * Check if a given object implements the BasicAuthenticationSettingModel interface.
 */
function instanceOfBasicAuthenticationSettingModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfBasicAuthenticationSettingModel = instanceOfBasicAuthenticationSettingModel;
function BasicAuthenticationSettingModelFromJSON(json) {
    return BasicAuthenticationSettingModelFromJSONTyped(json, false);
}
exports.BasicAuthenticationSettingModelFromJSON = BasicAuthenticationSettingModelFromJSON;
function BasicAuthenticationSettingModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'credentials': !(0, runtime_1.exists)(json, 'Credentials') ? undefined : (json['Credentials'].map(BasicAuthenticationCredentialModel_1.BasicAuthenticationCredentialModelFromJSON)),
        'isEnabled': !(0, runtime_1.exists)(json, 'IsEnabled') ? undefined : json['IsEnabled'],
        'noChallenge': !(0, runtime_1.exists)(json, 'NoChallenge') ? undefined : json['NoChallenge'],
    };
}
exports.BasicAuthenticationSettingModelFromJSONTyped = BasicAuthenticationSettingModelFromJSONTyped;
function BasicAuthenticationSettingModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Credentials': value.credentials === undefined ? undefined : (value.credentials.map(BasicAuthenticationCredentialModel_1.BasicAuthenticationCredentialModelToJSON)),
        'IsEnabled': value.isEnabled,
        'NoChallenge': value.noChallenge,
    };
}
exports.BasicAuthenticationSettingModelToJSON = BasicAuthenticationSettingModelToJSON;
//# sourceMappingURL=BasicAuthenticationSettingModel.js.map