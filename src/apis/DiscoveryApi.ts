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
  DeleteDiscoveryConnectionModel,
  DiscoveryConnectionsViewModel,
  DiscoveryServiceListApiResult,
  DiscoverySettingsApiModel,
  ExcludeFilter,
} from '../models/index';
import {
    DeleteDiscoveryConnectionModelFromJSON,
    DeleteDiscoveryConnectionModelToJSON,
    DiscoveryConnectionsViewModelFromJSON,
    DiscoveryConnectionsViewModelToJSON,
    DiscoveryServiceListApiResultFromJSON,
    DiscoveryServiceListApiResultToJSON,
    DiscoverySettingsApiModelFromJSON,
    DiscoverySettingsApiModelToJSON,
    ExcludeFilterFromJSON,
    ExcludeFilterToJSON,
} from '../models/index';

export interface DiscoveryConnectionByIdRequest {
    connectionId: string;
    type?: DiscoveryConnectionByIdTypeEnum;
}

export interface DiscoveryConnectionsRequest {
    name?: string;
    region?: string;
    type?: DiscoveryConnectionsTypeEnum;
    page?: number;
    pageSize?: number;
}

export interface DiscoveryCreateConnectionRequest {
    model: DiscoveryConnectionsViewModel;
}

export interface DiscoveryDeleteConnectionRequest {
    model: DeleteDiscoveryConnectionModel;
}

export interface DiscoveryEditConnectionRequest {
    model: DiscoveryConnectionsViewModel;
}

export interface DiscoveryExcludeRequest {
    model: ExcludeFilter;
}

export interface DiscoveryExportRequest {
    csvSeparator?: DiscoveryExportCsvSeparatorEnum;
}

export interface DiscoveryIgnoreRequest {
    serviceIds: Array<string>;
}

export interface DiscoveryIgnoreByFilterRequest {
    authority?: string;
    ipAddress?: string;
    secondLevelDomain?: string;
    topLevelDomain?: string;
    organizationName?: string;
    distance?: number;
    registeredDomain?: boolean;
}

export interface DiscoveryIncludeRequest {
    serviceIds: Array<string>;
}

export interface DiscoveryListRequest {
    page?: number;
    pageSize?: number;
}

export interface DiscoveryListByFilterRequest {
    authority?: string;
    ipAddress?: string;
    secondLevelDomain?: string;
    topLevelDomain?: string;
    organizationName?: string;
    distance?: number;
    registeredDomain?: boolean;
    status?: DiscoveryListByFilterStatusEnum;
    page?: number;
    pageSize?: number;
}

export interface DiscoveryUpdateSettingsRequest {
    model: DiscoverySettingsApiModel;
}

/**
 * 
 */
export class DiscoveryApi extends runtime.BaseAPI {

    /**
     * Get Connection By Id And Type.
     */
    async discoveryConnectionByIdRaw(requestParameters: DiscoveryConnectionByIdRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters['connectionId'] == null) {
            throw new runtime.RequiredError(
                'connectionId',
                'Required parameter "connectionId" was null or undefined when calling discoveryConnectionById().'
            );
        }

        const queryParameters: any = {};

        if (requestParameters['connectionId'] != null) {
            queryParameters['connectionId'] = requestParameters['connectionId'];
        }

        if (requestParameters['type'] != null) {
            queryParameters['type'] = requestParameters['type'];
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/discovery/connectionbyid`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Get Connection By Id And Type.
     */
    async discoveryConnectionById(requestParameters: DiscoveryConnectionByIdRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.discoveryConnectionByIdRaw(requestParameters, initOverrides);
    }

    /**
     * List Connections.
     */
    async discoveryConnectionsRaw(requestParameters: DiscoveryConnectionsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        const queryParameters: any = {};

        if (requestParameters['name'] != null) {
            queryParameters['name'] = requestParameters['name'];
        }

        if (requestParameters['region'] != null) {
            queryParameters['region'] = requestParameters['region'];
        }

        if (requestParameters['type'] != null) {
            queryParameters['type'] = requestParameters['type'];
        }

        if (requestParameters['page'] != null) {
            queryParameters['page'] = requestParameters['page'];
        }

        if (requestParameters['pageSize'] != null) {
            queryParameters['pageSize'] = requestParameters['pageSize'];
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/discovery/connections`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * List Connections.
     */
    async discoveryConnections(requestParameters: DiscoveryConnectionsRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.discoveryConnectionsRaw(requestParameters, initOverrides);
    }

    /**
     * Creates New Connection.
     */
    async discoveryCreateConnectionRaw(requestParameters: DiscoveryCreateConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters['model'] == null) {
            throw new runtime.RequiredError(
                'model',
                'Required parameter "model" was null or undefined when calling discoveryCreateConnection().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/discovery/createconnection`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: DiscoveryConnectionsViewModelToJSON(requestParameters['model']),
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Creates New Connection.
     */
    async discoveryCreateConnection(requestParameters: DiscoveryCreateConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.discoveryCreateConnectionRaw(requestParameters, initOverrides);
    }

    /**
     * Deletes Connection.
     */
    async discoveryDeleteConnectionRaw(requestParameters: DiscoveryDeleteConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters['model'] == null) {
            throw new runtime.RequiredError(
                'model',
                'Required parameter "model" was null or undefined when calling discoveryDeleteConnection().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/discovery/deleteconnection`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: DeleteDiscoveryConnectionModelToJSON(requestParameters['model']),
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Deletes Connection.
     */
    async discoveryDeleteConnection(requestParameters: DiscoveryDeleteConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.discoveryDeleteConnectionRaw(requestParameters, initOverrides);
    }

    /**
     * Edits Connection.
     */
    async discoveryEditConnectionRaw(requestParameters: DiscoveryEditConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters['model'] == null) {
            throw new runtime.RequiredError(
                'model',
                'Required parameter "model" was null or undefined when calling discoveryEditConnection().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/discovery/editconnection`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: DiscoveryConnectionsViewModelToJSON(requestParameters['model']),
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Edits Connection.
     */
    async discoveryEditConnection(requestParameters: DiscoveryEditConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.discoveryEditConnectionRaw(requestParameters, initOverrides);
    }

    /**
     * Returns exclude operation result.  This operation note override existing data, append to existing data.  If you want to override please use update-settings endpoint.
     */
    async discoveryExcludeRaw(requestParameters: DiscoveryExcludeRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>> {
        if (requestParameters['model'] == null) {
            throw new runtime.RequiredError(
                'model',
                'Required parameter "model" was null or undefined when calling discoveryExclude().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/discovery/exclude`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: ExcludeFilterToJSON(requestParameters['model']),
        }, initOverrides);

        return new runtime.JSONApiResponse<any>(response);
    }

    /**
     * Returns exclude operation result.  This operation note override existing data, append to existing data.  If you want to override please use update-settings endpoint.
     */
    async discoveryExclude(requestParameters: DiscoveryExcludeRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object> {
        const response = await this.discoveryExcludeRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Returns the all discovery services in the csv format as a downloadable file.
     */
    async discoveryExportRaw(requestParameters: DiscoveryExportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>> {
        const queryParameters: any = {};

        if (requestParameters['csvSeparator'] != null) {
            queryParameters['csvSeparator'] = requestParameters['csvSeparator'];
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/discovery/export`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse<any>(response);
    }

    /**
     * Returns the all discovery services in the csv format as a downloadable file.
     */
    async discoveryExport(requestParameters: DiscoveryExportRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object> {
        const response = await this.discoveryExportRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Ignores discovery service with given service ids.
     */
    async discoveryIgnoreRaw(requestParameters: DiscoveryIgnoreRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>> {
        if (requestParameters['serviceIds'] == null) {
            throw new runtime.RequiredError(
                'serviceIds',
                'Required parameter "serviceIds" was null or undefined when calling discoveryIgnore().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/discovery/ignore`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: requestParameters['serviceIds'],
        }, initOverrides);

        if (this.isJsonMime(response.headers.get('content-type'))) {
            return new runtime.JSONApiResponse<string>(response);
        } else {
            return new runtime.TextApiResponse(response) as any;
        }
    }

    /**
     * Ignores discovery service with given service ids.
     */
    async discoveryIgnore(requestParameters: DiscoveryIgnoreRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string> {
        const response = await this.discoveryIgnoreRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Ignores discovery services for selected filters.
     */
    async discoveryIgnoreByFilterRaw(requestParameters: DiscoveryIgnoreByFilterRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>> {
        const queryParameters: any = {};

        if (requestParameters['authority'] != null) {
            queryParameters['authority'] = requestParameters['authority'];
        }

        if (requestParameters['ipAddress'] != null) {
            queryParameters['ipAddress'] = requestParameters['ipAddress'];
        }

        if (requestParameters['secondLevelDomain'] != null) {
            queryParameters['secondLevelDomain'] = requestParameters['secondLevelDomain'];
        }

        if (requestParameters['topLevelDomain'] != null) {
            queryParameters['topLevelDomain'] = requestParameters['topLevelDomain'];
        }

        if (requestParameters['organizationName'] != null) {
            queryParameters['organizationName'] = requestParameters['organizationName'];
        }

        if (requestParameters['distance'] != null) {
            queryParameters['distance'] = requestParameters['distance'];
        }

        if (requestParameters['registeredDomain'] != null) {
            queryParameters['registeredDomain'] = requestParameters['registeredDomain'];
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/discovery/ignorebyfilter`,
            method: 'GET',
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
     * Ignores discovery services for selected filters.
     */
    async discoveryIgnoreByFilter(requestParameters: DiscoveryIgnoreByFilterRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string> {
        const response = await this.discoveryIgnoreByFilterRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Include discovery service with given service ids.
     */
    async discoveryIncludeRaw(requestParameters: DiscoveryIncludeRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>> {
        if (requestParameters['serviceIds'] == null) {
            throw new runtime.RequiredError(
                'serviceIds',
                'Required parameter "serviceIds" was null or undefined when calling discoveryInclude().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/discovery/include`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: requestParameters['serviceIds'],
        }, initOverrides);

        if (this.isJsonMime(response.headers.get('content-type'))) {
            return new runtime.JSONApiResponse<string>(response);
        } else {
            return new runtime.TextApiResponse(response) as any;
        }
    }

    /**
     * Include discovery service with given service ids.
     */
    async discoveryInclude(requestParameters: DiscoveryIncludeRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string> {
        const response = await this.discoveryIncludeRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the list discovery services.
     */
    async discoveryListRaw(requestParameters: DiscoveryListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<DiscoveryServiceListApiResult>> {
        const queryParameters: any = {};

        if (requestParameters['page'] != null) {
            queryParameters['page'] = requestParameters['page'];
        }

        if (requestParameters['pageSize'] != null) {
            queryParameters['pageSize'] = requestParameters['pageSize'];
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/discovery/list`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => DiscoveryServiceListApiResultFromJSON(jsonValue));
    }

    /**
     * Gets the list discovery services.
     */
    async discoveryList(requestParameters: DiscoveryListRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<DiscoveryServiceListApiResult> {
        const response = await this.discoveryListRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the list discovery services with filter.
     */
    async discoveryListByFilterRaw(requestParameters: DiscoveryListByFilterRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<DiscoveryServiceListApiResult>> {
        const queryParameters: any = {};

        if (requestParameters['authority'] != null) {
            queryParameters['authority'] = requestParameters['authority'];
        }

        if (requestParameters['ipAddress'] != null) {
            queryParameters['ipAddress'] = requestParameters['ipAddress'];
        }

        if (requestParameters['secondLevelDomain'] != null) {
            queryParameters['secondLevelDomain'] = requestParameters['secondLevelDomain'];
        }

        if (requestParameters['topLevelDomain'] != null) {
            queryParameters['topLevelDomain'] = requestParameters['topLevelDomain'];
        }

        if (requestParameters['organizationName'] != null) {
            queryParameters['organizationName'] = requestParameters['organizationName'];
        }

        if (requestParameters['distance'] != null) {
            queryParameters['distance'] = requestParameters['distance'];
        }

        if (requestParameters['registeredDomain'] != null) {
            queryParameters['registeredDomain'] = requestParameters['registeredDomain'];
        }

        if (requestParameters['status'] != null) {
            queryParameters['status'] = requestParameters['status'];
        }

        if (requestParameters['page'] != null) {
            queryParameters['page'] = requestParameters['page'];
        }

        if (requestParameters['pageSize'] != null) {
            queryParameters['pageSize'] = requestParameters['pageSize'];
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/discovery/listbyfilter`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => DiscoveryServiceListApiResultFromJSON(jsonValue));
    }

    /**
     * Gets the list discovery services with filter.
     */
    async discoveryListByFilter(requestParameters: DiscoveryListByFilterRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<DiscoveryServiceListApiResult> {
        const response = await this.discoveryListByFilterRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the discovery settings.
     */
    async discoverySettingsRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<DiscoverySettingsApiModel>> {
        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/discovery/settings`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => DiscoverySettingsApiModelFromJSON(jsonValue));
    }

    /**
     * Gets the discovery settings.
     */
    async discoverySettings(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<DiscoverySettingsApiModel> {
        const response = await this.discoverySettingsRaw(initOverrides);
        return await response.value();
    }

    /**
     * Updates discovery settings.
     */
    async discoveryUpdateSettingsRaw(requestParameters: DiscoveryUpdateSettingsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<DiscoverySettingsApiModel>> {
        if (requestParameters['model'] == null) {
            throw new runtime.RequiredError(
                'model',
                'Required parameter "model" was null or undefined when calling discoveryUpdateSettings().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/discovery/update-settings`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: DiscoverySettingsApiModelToJSON(requestParameters['model']),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => DiscoverySettingsApiModelFromJSON(jsonValue));
    }

    /**
     * Updates discovery settings.
     */
    async discoveryUpdateSettings(requestParameters: DiscoveryUpdateSettingsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<DiscoverySettingsApiModel> {
        const response = await this.discoveryUpdateSettingsRaw(requestParameters, initOverrides);
        return await response.value();
    }

}

/**
 * @export
 */
export const DiscoveryConnectionByIdTypeEnum = {
    Aws: 'Aws'
} as const;
export type DiscoveryConnectionByIdTypeEnum = typeof DiscoveryConnectionByIdTypeEnum[keyof typeof DiscoveryConnectionByIdTypeEnum];
/**
 * @export
 */
export const DiscoveryConnectionsTypeEnum = {
    Aws: 'Aws'
} as const;
export type DiscoveryConnectionsTypeEnum = typeof DiscoveryConnectionsTypeEnum[keyof typeof DiscoveryConnectionsTypeEnum];
/**
 * @export
 */
export const DiscoveryExportCsvSeparatorEnum = {
    Comma: 'Comma',
    Semicolon: 'Semicolon',
    Pipe: 'Pipe',
    Tab: 'Tab'
} as const;
export type DiscoveryExportCsvSeparatorEnum = typeof DiscoveryExportCsvSeparatorEnum[keyof typeof DiscoveryExportCsvSeparatorEnum];
/**
 * @export
 */
export const DiscoveryListByFilterStatusEnum = {
    Discovered: 'Discovered',
    Ignored: 'Ignored',
    Created: 'Created'
} as const;
export type DiscoveryListByFilterStatusEnum = typeof DiscoveryListByFilterStatusEnum[keyof typeof DiscoveryListByFilterStatusEnum];
