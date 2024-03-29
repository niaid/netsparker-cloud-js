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
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the AsanaTag interface.
 */
function instanceOfAsanaTag(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfAsanaTag = instanceOfAsanaTag;
function AsanaTagFromJSON(json) {
    return AsanaTagFromJSONTyped(json, false);
}
exports.AsanaTagFromJSON = AsanaTagFromJSON;
function AsanaTagFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'gid': !(0, runtime_1.exists)(json, 'Gid') ? undefined : json['Gid'],
        'name': !(0, runtime_1.exists)(json, 'Name') ? undefined : json['Name'],
    };
}
exports.AsanaTagFromJSONTyped = AsanaTagFromJSONTyped;
function AsanaTagToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Gid': value.gid,
        'Name': value.name,
    };
}
exports.AsanaTagToJSON = AsanaTagToJSON;
//# sourceMappingURL=AsanaTag.js.map