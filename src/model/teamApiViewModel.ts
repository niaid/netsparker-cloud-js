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

import { RequestFile } from './models';
import { ReducedMemberApiViewModel } from './reducedMemberApiViewModel';
import { RoleWebsiteGroupMappingApiViewModel } from './roleWebsiteGroupMappingApiViewModel';

export class TeamApiViewModel {
    /**
    * Id
    */
    'id'?: string;
    /**
    * Role Name field
    */
    'name'?: string;
    /**
    * Selected users
    */
    'members'?: Array<ReducedMemberApiViewModel>;
    'roleWebsiteGroupMappings'?: Array<RoleWebsiteGroupMappingApiViewModel>;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "id",
            "baseName": "Id",
            "type": "string"
        },
        {
            "name": "name",
            "baseName": "Name",
            "type": "string"
        },
        {
            "name": "members",
            "baseName": "Members",
            "type": "Array<ReducedMemberApiViewModel>"
        },
        {
            "name": "roleWebsiteGroupMappings",
            "baseName": "RoleWebsiteGroupMappings",
            "type": "Array<RoleWebsiteGroupMappingApiViewModel>"
        }    ];

    static getAttributeTypeMap() {
        return TeamApiViewModel.attributeTypeMap;
    }
}

