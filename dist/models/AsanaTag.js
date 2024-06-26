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
exports.AsanaTagToJSON = exports.AsanaTagFromJSONTyped = exports.AsanaTagFromJSON = exports.instanceOfAsanaTag = void 0;
/**
 * Check if a given object implements the AsanaTag interface.
 */
function instanceOfAsanaTag(value) {
    return true;
}
exports.instanceOfAsanaTag = instanceOfAsanaTag;
function AsanaTagFromJSON(json) {
    return AsanaTagFromJSONTyped(json, false);
}
exports.AsanaTagFromJSON = AsanaTagFromJSON;
function AsanaTagFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'gid': json['Gid'] == null ? undefined : json['Gid'],
        'name': json['Name'] == null ? undefined : json['Name'],
    };
}
exports.AsanaTagFromJSONTyped = AsanaTagFromJSONTyped;
function AsanaTagToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Gid': value['gid'],
        'Name': value['name'],
    };
}
exports.AsanaTagToJSON = AsanaTagToJSON;
//# sourceMappingURL=AsanaTag.js.map