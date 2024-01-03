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
import { exists } from '../runtime';
import { RoleWebsiteGroupMappingApiModelFromJSON, RoleWebsiteGroupMappingApiModelToJSON, } from './RoleWebsiteGroupMappingApiModel';
/**
 * Check if a given object implements the NewTeamApiModel interface.
 */
export function instanceOfNewTeamApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "name" in value;
    return isInstance;
}
export function NewTeamApiModelFromJSON(json) {
    return NewTeamApiModelFromJSONTyped(json, false);
}
export function NewTeamApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'roleWebsiteGroupMappings': !exists(json, 'RoleWebsiteGroupMappings') ? undefined : (json['RoleWebsiteGroupMappings'].map(RoleWebsiteGroupMappingApiModelFromJSON)),
        'name': json['Name'],
        'members': !exists(json, 'Members') ? undefined : json['Members'],
    };
}
export function NewTeamApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'RoleWebsiteGroupMappings': value.roleWebsiteGroupMappings === undefined ? undefined : (value.roleWebsiteGroupMappings.map(RoleWebsiteGroupMappingApiModelToJSON)),
        'Name': value.name,
        'Members': value.members,
    };
}
//# sourceMappingURL=NewTeamApiModel.js.map