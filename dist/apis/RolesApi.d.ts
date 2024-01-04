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
export interface RolesDeleteRequest {
    id: string;
}
export interface RolesGetRequest {
    id: string;
}
export interface RolesListRequest {
    page?: number;
    pageSize?: number;
}
export interface RolesNewRequest {
    model: NewRoleApiModel;
}
export interface RolesUpdateRequest {
    model: UpdateRoleApiModel;
}
/**
 *
 */
export declare class RolesApi extends runtime.BaseAPI {
    /**
     * Deletes a role.
     */
    rolesDeleteRaw(requestParameters: RolesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>>;
    /**
     * Deletes a role.
     */
    rolesDelete(requestParameters: RolesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string>;
    /**
     * Gets the role by the specified id.
     */
    rolesGetRaw(requestParameters: RolesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiViewModel>>;
    /**
     * Gets the role by the specified id.
     */
    rolesGet(requestParameters: RolesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiViewModel>;
    /**
     * Gets the list of roles.
     */
    rolesListRaw(requestParameters: RolesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiModelListApiResult>>;
    /**
     * Gets the list of roles.
     */
    rolesList(requestParameters?: RolesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiModelListApiResult>;
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
    rolesNewRaw(requestParameters: RolesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiViewModel>>;
    /**
     * Creates a new role
     */
    rolesNew(requestParameters: RolesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiViewModel>;
    /**
     * Updates a role
     */
    rolesUpdateRaw(requestParameters: RolesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiViewModel>>;
    /**
     * Updates a role
     */
    rolesUpdate(requestParameters: RolesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiViewModel>;
}
