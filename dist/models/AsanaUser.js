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
exports.AsanaUserToJSON = exports.AsanaUserFromJSONTyped = exports.AsanaUserFromJSON = exports.instanceOfAsanaUser = void 0;
/**
 * Check if a given object implements the AsanaUser interface.
 */
function instanceOfAsanaUser(value) {
    return true;
}
exports.instanceOfAsanaUser = instanceOfAsanaUser;
function AsanaUserFromJSON(json) {
    return AsanaUserFromJSONTyped(json, false);
}
exports.AsanaUserFromJSON = AsanaUserFromJSON;
function AsanaUserFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'email': json['email'] == null ? undefined : json['email'],
        'gid': json['gid'] == null ? undefined : json['gid'],
        'name': json['name'] == null ? undefined : json['name'],
        'displayName': json['DisplayName'] == null ? undefined : json['DisplayName'],
    };
}
exports.AsanaUserFromJSONTyped = AsanaUserFromJSONTyped;
function AsanaUserToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'email': value['email'],
        'gid': value['gid'],
        'name': value['name'],
    };
}
exports.AsanaUserToJSON = AsanaUserToJSON;
//# sourceMappingURL=AsanaUser.js.map