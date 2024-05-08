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
exports.ExcludedLinkModelToJSON = exports.ExcludedLinkModelFromJSONTyped = exports.ExcludedLinkModelFromJSON = exports.instanceOfExcludedLinkModel = void 0;
/**
 * Check if a given object implements the ExcludedLinkModel interface.
 */
function instanceOfExcludedLinkModel(value) {
    if (!('regexPattern' in value))
        return false;
    return true;
}
exports.instanceOfExcludedLinkModel = instanceOfExcludedLinkModel;
function ExcludedLinkModelFromJSON(json) {
    return ExcludedLinkModelFromJSONTyped(json, false);
}
exports.ExcludedLinkModelFromJSON = ExcludedLinkModelFromJSON;
function ExcludedLinkModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'regexPattern': json['RegexPattern'],
    };
}
exports.ExcludedLinkModelFromJSONTyped = ExcludedLinkModelFromJSONTyped;
function ExcludedLinkModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'RegexPattern': value['regexPattern'],
    };
}
exports.ExcludedLinkModelToJSON = ExcludedLinkModelToJSON;
//# sourceMappingURL=ExcludedLinkModel.js.map