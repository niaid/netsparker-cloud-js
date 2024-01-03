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
import type { ReducedMemberApiViewModel } from './ReducedMemberApiViewModel';
import type { RoleWebsiteGroupMappingDto } from './RoleWebsiteGroupMappingDto';
/**
 *
 * @export
 * @interface TeamApiViewModel
 */
export interface TeamApiViewModel {
    /**
     * Id
     * @type {string}
     * @memberof TeamApiViewModel
     */
    id?: string;
    /**
     * Role Name field
     * @type {string}
     * @memberof TeamApiViewModel
     */
    name?: string;
    /**
     * Selected users
     * @type {Array<ReducedMemberApiViewModel>}
     * @memberof TeamApiViewModel
     */
    members?: Array<ReducedMemberApiViewModel>;
    /**
     *
     * @type {Array<RoleWebsiteGroupMappingDto>}
     * @memberof TeamApiViewModel
     */
    roleWebsiteGroupMappings?: Array<RoleWebsiteGroupMappingDto>;
}
/**
 * Check if a given object implements the TeamApiViewModel interface.
 */
export declare function instanceOfTeamApiViewModel(value: object): boolean;
export declare function TeamApiViewModelFromJSON(json: any): TeamApiViewModel;
export declare function TeamApiViewModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): TeamApiViewModel;
export declare function TeamApiViewModelToJSON(value?: TeamApiViewModel | null): any;