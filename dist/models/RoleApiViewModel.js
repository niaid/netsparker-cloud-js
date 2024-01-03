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
exports.RoleApiViewModelToJSON = exports.RoleApiViewModelFromJSONTyped = exports.RoleApiViewModelFromJSON = exports.instanceOfRoleApiViewModel = void 0;
const runtime_1 = require("../runtime");
const PermissionApiModel_1 = require("./PermissionApiModel");
/**
 * Check if a given object implements the RoleApiViewModel interface.
 */
function instanceOfRoleApiViewModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfRoleApiViewModel = instanceOfRoleApiViewModel;
function RoleApiViewModelFromJSON(json) {
    return RoleApiViewModelFromJSONTyped(json, false);
}
exports.RoleApiViewModelFromJSON = RoleApiViewModelFromJSON;
function RoleApiViewModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': !(0, runtime_1.exists)(json, 'Id') ? undefined : json['Id'],
        'name': !(0, runtime_1.exists)(json, 'Name') ? undefined : json['Name'],
        'permissions': !(0, runtime_1.exists)(json, 'Permissions') ? undefined : (json['Permissions'].map(PermissionApiModel_1.PermissionApiModelFromJSON)),
    };
}
exports.RoleApiViewModelFromJSONTyped = RoleApiViewModelFromJSONTyped;
function RoleApiViewModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Id': value.id,
        'Name': value.name,
        'Permissions': value.permissions === undefined ? undefined : (value.permissions.map(PermissionApiModel_1.PermissionApiModelToJSON)),
    };
}
exports.RoleApiViewModelToJSON = RoleApiViewModelToJSON;
//# sourceMappingURL=RoleApiViewModel.js.map