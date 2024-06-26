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
exports.PermissionApiModelToJSON = exports.PermissionApiModelFromJSONTyped = exports.PermissionApiModelFromJSON = exports.instanceOfPermissionApiModel = void 0;
/**
 * Check if a given object implements the PermissionApiModel interface.
 */
function instanceOfPermissionApiModel(value) {
    return true;
}
exports.instanceOfPermissionApiModel = instanceOfPermissionApiModel;
function PermissionApiModelFromJSON(json) {
    return PermissionApiModelFromJSONTyped(json, false);
}
exports.PermissionApiModelFromJSON = PermissionApiModelFromJSON;
function PermissionApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'id': json['Id'] == null ? undefined : json['Id'],
        'name': json['Name'] == null ? undefined : json['Name'],
        'information': json['Information'] == null ? undefined : json['Information'],
    };
}
exports.PermissionApiModelFromJSONTyped = PermissionApiModelFromJSONTyped;
function PermissionApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Id': value['id'],
        'Name': value['name'],
        'Information': value['information'],
    };
}
exports.PermissionApiModelToJSON = PermissionApiModelToJSON;
//# sourceMappingURL=PermissionApiModel.js.map