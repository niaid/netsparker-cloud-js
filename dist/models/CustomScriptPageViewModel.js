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
exports.CustomScriptPageViewModelToJSON = exports.CustomScriptPageViewModelFromJSONTyped = exports.CustomScriptPageViewModelFromJSON = exports.instanceOfCustomScriptPageViewModel = void 0;
/**
 * Check if a given object implements the CustomScriptPageViewModel interface.
 */
function instanceOfCustomScriptPageViewModel(value) {
    let isInstance = true;
    isInstance = isInstance && "key" in value;
    isInstance = isInstance && "value" in value;
    return isInstance;
}
exports.instanceOfCustomScriptPageViewModel = instanceOfCustomScriptPageViewModel;
function CustomScriptPageViewModelFromJSON(json) {
    return CustomScriptPageViewModelFromJSONTyped(json, false);
}
exports.CustomScriptPageViewModelFromJSON = CustomScriptPageViewModelFromJSON;
function CustomScriptPageViewModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'key': json['key'],
        'value': json['value'],
    };
}
exports.CustomScriptPageViewModelFromJSONTyped = CustomScriptPageViewModelFromJSONTyped;
function CustomScriptPageViewModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'key': value.key,
        'value': value.value,
    };
}
exports.CustomScriptPageViewModelToJSON = CustomScriptPageViewModelToJSON;
//# sourceMappingURL=CustomScriptPageViewModel.js.map