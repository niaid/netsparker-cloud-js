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
exports.SecurityCheckSettingToJSON = exports.SecurityCheckSettingFromJSONTyped = exports.SecurityCheckSettingFromJSON = exports.instanceOfSecurityCheckSetting = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the SecurityCheckSetting interface.
 */
function instanceOfSecurityCheckSetting(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfSecurityCheckSetting = instanceOfSecurityCheckSetting;
function SecurityCheckSettingFromJSON(json) {
    return SecurityCheckSettingFromJSONTyped(json, false);
}
exports.SecurityCheckSettingFromJSON = SecurityCheckSettingFromJSON;
function SecurityCheckSettingFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'name': !(0, runtime_1.exists)(json, 'Name') ? undefined : json['Name'],
        'value': !(0, runtime_1.exists)(json, 'Value') ? undefined : json['Value'],
    };
}
exports.SecurityCheckSettingFromJSONTyped = SecurityCheckSettingFromJSONTyped;
function SecurityCheckSettingToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Name': value.name,
        'Value': value.value,
    };
}
exports.SecurityCheckSettingToJSON = SecurityCheckSettingToJSON;
//# sourceMappingURL=SecurityCheckSetting.js.map