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

import { exists, mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface RoleWebsiteGroupMappingDto
 */
export interface RoleWebsiteGroupMappingDto {
    /**
     * 
     * @type {string}
     * @memberof RoleWebsiteGroupMappingDto
     */
    roleName?: string;
    /**
     * 
     * @type {string}
     * @memberof RoleWebsiteGroupMappingDto
     */
    roleId?: string;
    /**
     * 
     * @type {string}
     * @memberof RoleWebsiteGroupMappingDto
     */
    websiteGroupName?: string;
    /**
     * 
     * @type {string}
     * @memberof RoleWebsiteGroupMappingDto
     */
    websiteGroupId?: string;
}

/**
 * Check if a given object implements the RoleWebsiteGroupMappingDto interface.
 */
export function instanceOfRoleWebsiteGroupMappingDto(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function RoleWebsiteGroupMappingDtoFromJSON(json: any): RoleWebsiteGroupMappingDto {
    return RoleWebsiteGroupMappingDtoFromJSONTyped(json, false);
}

export function RoleWebsiteGroupMappingDtoFromJSONTyped(json: any, ignoreDiscriminator: boolean): RoleWebsiteGroupMappingDto {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'roleName': !exists(json, 'RoleName') ? undefined : json['RoleName'],
        'roleId': !exists(json, 'RoleId') ? undefined : json['RoleId'],
        'websiteGroupName': !exists(json, 'WebsiteGroupName') ? undefined : json['WebsiteGroupName'],
        'websiteGroupId': !exists(json, 'WebsiteGroupId') ? undefined : json['WebsiteGroupId'],
    };
}

export function RoleWebsiteGroupMappingDtoToJSON(value?: RoleWebsiteGroupMappingDto | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'RoleName': value.roleName,
        'RoleId': value.roleId,
        'WebsiteGroupName': value.websiteGroupName,
        'WebsiteGroupId': value.websiteGroupId,
    };
}

