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
exports.UpdateRoleApiModelToJSON = exports.UpdateRoleApiModelFromJSONTyped = exports.UpdateRoleApiModelFromJSON = exports.instanceOfUpdateRoleApiModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the UpdateRoleApiModel interface.
 */
function instanceOfUpdateRoleApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "id" in value;
    isInstance = isInstance && "name" in value;
    return isInstance;
}
exports.instanceOfUpdateRoleApiModel = instanceOfUpdateRoleApiModel;
function UpdateRoleApiModelFromJSON(json) {
    return UpdateRoleApiModelFromJSONTyped(json, false);
}
exports.UpdateRoleApiModelFromJSON = UpdateRoleApiModelFromJSON;
function UpdateRoleApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': json['Id'],
        'name': json['Name'],
        'permissions': !(0, runtime_1.exists)(json, 'Permissions') ? undefined : json['Permissions'],
    };
}
exports.UpdateRoleApiModelFromJSONTyped = UpdateRoleApiModelFromJSONTyped;
function UpdateRoleApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Id': value.id,
        'Name': value.name,
        'Permissions': value.permissions,
    };
}
exports.UpdateRoleApiModelToJSON = UpdateRoleApiModelToJSON;
//# sourceMappingURL=UpdateRoleApiModel.js.map