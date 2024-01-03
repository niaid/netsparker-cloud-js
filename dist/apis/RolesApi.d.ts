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
import * as runtime from '../runtime';
import type { NewRoleApiModel, PermissionApiModel, RoleApiModelListApiResult, RoleApiViewModel, UpdateRoleApiModel } from '../models/index';
export interface RolesApiRolesDeleteRequest {
    id: string;
}
export interface RolesApiRolesGetRequest {
    id: string;
}
export interface RolesApiRolesListRequest {
    page?: number;
    pageSize?: number;
}
export interface RolesApiRolesNewRequest {
    model: NewRoleApiModel;
}
export interface RolesApiRolesUpdateRequest {
    model: UpdateRoleApiModel;
}
/**
 *
 */
export declare class RolesApi extends runtime.BaseAPI {
    /**
     * Deletes a role.
     */
    rolesDeleteRaw(requestParameters: RolesApiRolesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>>;
    /**
     * Deletes a role.
     */
    rolesDelete(requestParameters: RolesApiRolesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string>;
    /**
     * Gets the role by the specified id.
     */
    rolesGetRaw(requestParameters: RolesApiRolesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiViewModel>>;
    /**
     * Gets the role by the specified id.
     */
    rolesGet(requestParameters: RolesApiRolesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiViewModel>;
    /**
     * Gets the list of roles.
     */
    rolesListRaw(requestParameters: RolesApiRolesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiModelListApiResult>>;
    /**
     * Gets the list of roles.
     */
    rolesList(requestParameters?: RolesApiRolesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiModelListApiResult>;
    /**
     * Gets the list of permissions.
     */
    rolesListPermissionsRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<Array<PermissionApiModel>>>;
    /**
     * Gets the list of permissions.
     */
    rolesListPermissions(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<Array<PermissionApiModel>>;
    /**
     * Creates a new role
     */
    rolesNewRaw(requestParameters: RolesApiRolesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiViewModel>>;
    /**
     * Creates a new role
     */
    rolesNew(requestParameters: RolesApiRolesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiViewModel>;
    /**
     * Updates a role
     */
    rolesUpdateRaw(requestParameters: RolesApiRolesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiViewModel>>;
    /**
     * Updates a role
     */
    rolesUpdate(requestParameters: RolesApiRolesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiViewModel>;
}
