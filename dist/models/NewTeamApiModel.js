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
exports.NewTeamApiModelToJSON = exports.NewTeamApiModelFromJSONTyped = exports.NewTeamApiModelFromJSON = exports.instanceOfNewTeamApiModel = void 0;
const runtime_1 = require("../runtime");
const RoleWebsiteGroupMappingApiModel_1 = require("./RoleWebsiteGroupMappingApiModel");
/**
 * Check if a given object implements the NewTeamApiModel interface.
 */
function instanceOfNewTeamApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "name" in value;
    return isInstance;
}
exports.instanceOfNewTeamApiModel = instanceOfNewTeamApiModel;
function NewTeamApiModelFromJSON(json) {
    return NewTeamApiModelFromJSONTyped(json, false);
}
exports.NewTeamApiModelFromJSON = NewTeamApiModelFromJSON;
function NewTeamApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'roleWebsiteGroupMappings': !(0, runtime_1.exists)(json, 'RoleWebsiteGroupMappings') ? undefined : (json['RoleWebsiteGroupMappings'].map(RoleWebsiteGroupMappingApiModel_1.RoleWebsiteGroupMappingApiModelFromJSON)),
        'name': json['Name'],
        'members': !(0, runtime_1.exists)(json, 'Members') ? undefined : json['Members'],
    };
}
exports.NewTeamApiModelFromJSONTyped = NewTeamApiModelFromJSONTyped;
function NewTeamApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'RoleWebsiteGroupMappings': value.roleWebsiteGroupMappings === undefined ? undefined : (value.roleWebsiteGroupMappings.map(RoleWebsiteGroupMappingApiModel_1.RoleWebsiteGroupMappingApiModelToJSON)),
        'Name': value.name,
        'Members': value.members,
    };
}
exports.NewTeamApiModelToJSON = NewTeamApiModelToJSON;
//# sourceMappingURL=NewTeamApiModel.js.map