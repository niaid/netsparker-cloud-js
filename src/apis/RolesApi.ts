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


import * as runtime from '../runtime';
import type {
  BaseResponseApiModel,
  NewRoleApiModel,
  PermissionApiModel,
  RoleApiModelListApiResult,
  RoleApiViewModel,
  UpdateRoleApiModel,
} from '../models/index';
import {
    BaseResponseApiModelFromJSON,
    BaseResponseApiModelToJSON,
    NewRoleApiModelFromJSON,
    NewRoleApiModelToJSON,
    PermissionApiModelFromJSON,
    PermissionApiModelToJSON,
    RoleApiModelListApiResultFromJSON,
    RoleApiModelListApiResultToJSON,
    RoleApiViewModelFromJSON,
    RoleApiViewModelToJSON,
    UpdateRoleApiModelFromJSON,
    UpdateRoleApiModelToJSON,
} from '../models/index';

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
export class RolesApi extends runtime.BaseAPI {

    /**
     * Deletes a role.
     */
    async rolesDeleteRaw(requestParameters: RolesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>> {
        if (requestParameters.id === null || requestParameters.id === undefined) {
            throw new runtime.RequiredError('id','Required parameter requestParameters.id was null or undefined when calling rolesDelete.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/roles/delete/{id}`.replace(`{${"id"}}`, encodeURIComponent(String(requestParameters.id))),
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        if (this.isJsonMime(response.headers.get('content-type'))) {
            return new runtime.JSONApiResponse<string>(response);
        } else {
            return new runtime.TextApiResponse(response) as any;
        }
    }

    /**
     * Deletes a role.
     */
    async rolesDelete(requestParameters: RolesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string> {
        const response = await this.rolesDeleteRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the role by the specified id.
     */
    async rolesGetRaw(requestParameters: RolesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiViewModel>> {
        if (requestParameters.id === null || requestParameters.id === undefined) {
            throw new runtime.RequiredError('id','Required parameter requestParameters.id was null or undefined when calling rolesGet.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/roles/get/{id}`.replace(`{${"id"}}`, encodeURIComponent(String(requestParameters.id))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => RoleApiViewModelFromJSON(jsonValue));
    }

    /**
     * Gets the role by the specified id.
     */
    async rolesGet(requestParameters: RolesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiViewModel> {
        const response = await this.rolesGetRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the list of roles.
     */
    async rolesListRaw(requestParameters: RolesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiModelListApiResult>> {
        const queryParameters: any = {};

        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }

        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/roles/list`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => RoleApiModelListApiResultFromJSON(jsonValue));
    }

    /**
     * Gets the list of roles.
     */
    async rolesList(requestParameters: RolesListRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiModelListApiResult> {
        const response = await this.rolesListRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the list of permissions.
     */
    async rolesListPermissionsRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<Array<PermissionApiModel>>> {
        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/roles/listpermissions`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => jsonValue.map(PermissionApiModelFromJSON));
    }

    /**
     * Gets the list of permissions.
     */
    async rolesListPermissions(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<Array<PermissionApiModel>> {
        const response = await this.rolesListPermissionsRaw(initOverrides);
        return await response.value();
    }

    /**
     * Creates a new role
     */
    async rolesNewRaw(requestParameters: RolesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiViewModel>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling rolesNew.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/roles/new`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: NewRoleApiModelToJSON(requestParameters.model),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => RoleApiViewModelFromJSON(jsonValue));
    }

    /**
     * Creates a new role
     */
    async rolesNew(requestParameters: RolesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiViewModel> {
        const response = await this.rolesNewRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Updates a role
     */
    async rolesUpdateRaw(requestParameters: RolesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<RoleApiViewModel>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling rolesUpdate.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/roles/update`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: UpdateRoleApiModelToJSON(requestParameters.model),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => RoleApiViewModelFromJSON(jsonValue));
    }

    /**
     * Updates a role
     */
    async rolesUpdate(requestParameters: RolesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<RoleApiViewModel> {
        const response = await this.rolesUpdateRaw(requestParameters, initOverrides);
        return await response.value();
    }

}