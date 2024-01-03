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
export declare function instanceOfRoleWebsiteGroupMappingDto(value: object): boolean;
export declare function RoleWebsiteGroupMappingDtoFromJSON(json: any): RoleWebsiteGroupMappingDto;
export declare function RoleWebsiteGroupMappingDtoFromJSONTyped(json: any, ignoreDiscriminator: boolean): RoleWebsiteGroupMappingDto;
export declare function RoleWebsiteGroupMappingDtoToJSON(value?: RoleWebsiteGroupMappingDto | null): any;