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
exports.RoleWebsiteGroupMappingApiModelToJSON = exports.RoleWebsiteGroupMappingApiModelFromJSONTyped = exports.RoleWebsiteGroupMappingApiModelFromJSON = exports.instanceOfRoleWebsiteGroupMappingApiModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the RoleWebsiteGroupMappingApiModel interface.
 */
function instanceOfRoleWebsiteGroupMappingApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "roleId" in value;
    return isInstance;
}
exports.instanceOfRoleWebsiteGroupMappingApiModel = instanceOfRoleWebsiteGroupMappingApiModel;
function RoleWebsiteGroupMappingApiModelFromJSON(json) {
    return RoleWebsiteGroupMappingApiModelFromJSONTyped(json, false);
}
exports.RoleWebsiteGroupMappingApiModelFromJSON = RoleWebsiteGroupMappingApiModelFromJSON;
function RoleWebsiteGroupMappingApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'websiteGroupId': !(0, runtime_1.exists)(json, 'WebsiteGroupId') ? undefined : json['WebsiteGroupId'],
        'roleId': json['RoleId'],
    };
}
exports.RoleWebsiteGroupMappingApiModelFromJSONTyped = RoleWebsiteGroupMappingApiModelFromJSONTyped;
function RoleWebsiteGroupMappingApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'WebsiteGroupId': value.websiteGroupId,
        'RoleId': value.roleId,
    };
}
exports.RoleWebsiteGroupMappingApiModelToJSON = RoleWebsiteGroupMappingApiModelToJSON;
//# sourceMappingURL=RoleWebsiteGroupMappingApiModel.js.map