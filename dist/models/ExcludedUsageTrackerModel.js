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
exports.ExcludedUsageTrackerModelToJSON = exports.ExcludedUsageTrackerModelFromJSONTyped = exports.ExcludedUsageTrackerModelFromJSON = exports.instanceOfExcludedUsageTrackerModel = void 0;
/**
 * Check if a given object implements the ExcludedUsageTrackerModel interface.
 */
function instanceOfExcludedUsageTrackerModel(value) {
    if (!('url' in value))
        return false;
    return true;
}
exports.instanceOfExcludedUsageTrackerModel = instanceOfExcludedUsageTrackerModel;
function ExcludedUsageTrackerModelFromJSON(json) {
    return ExcludedUsageTrackerModelFromJSONTyped(json, false);
}
exports.ExcludedUsageTrackerModelFromJSON = ExcludedUsageTrackerModelFromJSON;
function ExcludedUsageTrackerModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'url': json['Url'],
    };
}
exports.ExcludedUsageTrackerModelFromJSONTyped = ExcludedUsageTrackerModelFromJSONTyped;
function ExcludedUsageTrackerModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Url': value['url'],
    };
}
exports.ExcludedUsageTrackerModelToJSON = ExcludedUsageTrackerModelToJSON;
//# sourceMappingURL=ExcludedUsageTrackerModel.js.map