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
exports.CustomHttpHeaderSettingToJSON = exports.CustomHttpHeaderSettingFromJSONTyped = exports.CustomHttpHeaderSettingFromJSON = exports.instanceOfCustomHttpHeaderSetting = exports.CustomHttpHeaderSettingAttackModeEnum = void 0;
const runtime_1 = require("../runtime");
/**
 * @export
 */
exports.CustomHttpHeaderSettingAttackModeEnum = {
    None: 'None',
    Optimized: 'Optimized',
    Full: 'Full'
};
/**
 * Check if a given object implements the CustomHttpHeaderSetting interface.
 */
function instanceOfCustomHttpHeaderSetting(value) {
    let isInstance = true;
    isInstance = isInstance && "name" in value;
    return isInstance;
}
exports.instanceOfCustomHttpHeaderSetting = instanceOfCustomHttpHeaderSetting;
function CustomHttpHeaderSettingFromJSON(json) {
    return CustomHttpHeaderSettingFromJSONTyped(json, false);
}
exports.CustomHttpHeaderSettingFromJSON = CustomHttpHeaderSettingFromJSON;
function CustomHttpHeaderSettingFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'attackMode': !(0, runtime_1.exists)(json, 'AttackMode') ? undefined : json['AttackMode'],
        'enabled': !(0, runtime_1.exists)(json, 'Enabled') ? undefined : json['Enabled'],
        'name': json['Name'],
        'value': !(0, runtime_1.exists)(json, 'Value') ? undefined : json['Value'],
    };
}
exports.CustomHttpHeaderSettingFromJSONTyped = CustomHttpHeaderSettingFromJSONTyped;
function CustomHttpHeaderSettingToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AttackMode': value.attackMode,
        'Enabled': value.enabled,
        'Name': value.name,
        'Value': value.value,
    };
}
exports.CustomHttpHeaderSettingToJSON = CustomHttpHeaderSettingToJSON;
//# sourceMappingURL=CustomHttpHeaderSetting.js.map