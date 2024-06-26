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
exports.BrowserSettingToJSON = exports.BrowserSettingFromJSONTyped = exports.BrowserSettingFromJSON = exports.instanceOfBrowserSetting = void 0;
/**
 * Check if a given object implements the BrowserSetting interface.
 */
function instanceOfBrowserSetting(value) {
    if (!('name' in value))
        return false;
    return true;
}
exports.instanceOfBrowserSetting = instanceOfBrowserSetting;
function BrowserSettingFromJSON(json) {
    return BrowserSettingFromJSONTyped(json, false);
}
exports.BrowserSettingFromJSON = BrowserSettingFromJSON;
function BrowserSettingFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'enabled': json['Enabled'] == null ? undefined : json['Enabled'],
        'name': json['Name'],
        'readOnly': json['ReadOnly'] == null ? undefined : json['ReadOnly'],
    };
}
exports.BrowserSettingFromJSONTyped = BrowserSettingFromJSONTyped;
function BrowserSettingToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Enabled': value['enabled'],
        'Name': value['name'],
        'ReadOnly': value['readOnly'],
    };
}
exports.BrowserSettingToJSON = BrowserSettingToJSON;
//# sourceMappingURL=BrowserSetting.js.map