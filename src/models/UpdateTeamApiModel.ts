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

import { mapValues } from '../runtime';
import type { RoleWebsiteGroupMappingApiModel } from './RoleWebsiteGroupMappingApiModel';
import {
    RoleWebsiteGroupMappingApiModelFromJSON,
    RoleWebsiteGroupMappingApiModelFromJSONTyped,
    RoleWebsiteGroupMappingApiModelToJSON,
} from './RoleWebsiteGroupMappingApiModel';

/**
 * 
 * @export
 * @interface UpdateTeamApiModel
 */
export interface UpdateTeamApiModel {
    /**
     * 
     * @type {Array<RoleWebsiteGroupMappingApiModel>}
     * @memberof UpdateTeamApiModel
     */
    roleWebsiteGroupMappings?: Array<RoleWebsiteGroupMappingApiModel>;
    /**
     * Id
     * @type {string}
     * @memberof UpdateTeamApiModel
     */
    id: string;
    /**
     * Role Name field
     * @type {string}
     * @memberof UpdateTeamApiModel
     */
    name: string;
    /**
     * users
     * @type {Array<string>}
     * @memberof UpdateTeamApiModel
     */
    members?: Array<string>;
}

/**
 * Check if a given object implements the UpdateTeamApiModel interface.
 */
export function instanceOfUpdateTeamApiModel(value: object): boolean {
    if (!('id' in value)) return false;
    if (!('name' in value)) return false;
    return true;
}

export function UpdateTeamApiModelFromJSON(json: any): UpdateTeamApiModel {
    return UpdateTeamApiModelFromJSONTyped(json, false);
}

export function UpdateTeamApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateTeamApiModel {
    if (json == null) {
        return json;
    }
    return {
        
        'roleWebsiteGroupMappings': json['RoleWebsiteGroupMappings'] == null ? undefined : ((json['RoleWebsiteGroupMappings'] as Array<any>).map(RoleWebsiteGroupMappingApiModelFromJSON)),
        'id': json['Id'],
        'name': json['Name'],
        'members': json['Members'] == null ? undefined : json['Members'],
    };
}

export function UpdateTeamApiModelToJSON(value?: UpdateTeamApiModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'RoleWebsiteGroupMappings': value['roleWebsiteGroupMappings'] == null ? undefined : ((value['roleWebsiteGroupMappings'] as Array<any>).map(RoleWebsiteGroupMappingApiModelToJSON)),
        'Id': value['id'],
        'Name': value['name'],
        'Members': value['members'],
    };
}

