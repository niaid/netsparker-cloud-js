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
exports.TagViewModelToJSON = exports.TagViewModelFromJSONTyped = exports.TagViewModelFromJSON = exports.instanceOfTagViewModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the TagViewModel interface.
 */
function instanceOfTagViewModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfTagViewModel = instanceOfTagViewModel;
function TagViewModelFromJSON(json) {
    return TagViewModelFromJSONTyped(json, false);
}
exports.TagViewModelFromJSON = TagViewModelFromJSON;
function TagViewModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': !(0, runtime_1.exists)(json, 'Id') ? undefined : json['Id'],
        'value': !(0, runtime_1.exists)(json, 'Value') ? undefined : json['Value'],
    };
}
exports.TagViewModelFromJSONTyped = TagViewModelFromJSONTyped;
function TagViewModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Id': value.id,
        'Value': value.value,
    };
}
exports.TagViewModelToJSON = TagViewModelToJSON;
//# sourceMappingURL=TagViewModel.js.map