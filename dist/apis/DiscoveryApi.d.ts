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
import type { DeleteDiscoveryConnectionModel, DiscoveryConnectionsViewModel, DiscoveryServiceListApiResult, DiscoverySettingsApiModel, ExcludeFilter } from '../models/index';
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
export declare class DiscoveryApi extends runtime.BaseAPI {
    /**
     * Get Connection By Id And Type.
     */
    discoveryConnectionByIdRaw(requestParameters: DiscoveryConnectionByIdRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Get Connection By Id And Type.
     */
    discoveryConnectionById(requestParameters: DiscoveryConnectionByIdRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * List Connections.
     */
    discoveryConnectionsRaw(requestParameters: DiscoveryConnectionsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * List Connections.
     */
    discoveryConnections(requestParameters?: DiscoveryConnectionsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Creates New Connection.
     */
    discoveryCreateConnectionRaw(requestParameters: DiscoveryCreateConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Creates New Connection.
     */
    discoveryCreateConnection(requestParameters: DiscoveryCreateConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Deletes Connection.
     */
    discoveryDeleteConnectionRaw(requestParameters: DiscoveryDeleteConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Deletes Connection.
     */
    discoveryDeleteConnection(requestParameters: DiscoveryDeleteConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Edits Connection.
     */
    discoveryEditConnectionRaw(requestParameters: DiscoveryEditConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Edits Connection.
     */
    discoveryEditConnection(requestParameters: DiscoveryEditConnectionRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Returns exclude operation result.  This operation note override existing data, append to existing data.  If you want to override please use update-settings endpoint.
     */
    discoveryExcludeRaw(requestParameters: DiscoveryExcludeRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>>;
    /**
     * Returns exclude operation result.  This operation note override existing data, append to existing data.  If you want to override please use update-settings endpoint.
     */
    discoveryExclude(requestParameters: DiscoveryExcludeRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object>;
    /**
     * Returns the all discovery services in the csv format as a downloadable file.
     */
    discoveryExportRaw(requestParameters: DiscoveryExportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>>;
    /**
     * Returns the all discovery services in the csv format as a downloadable file.
     */
    discoveryExport(requestParameters?: DiscoveryExportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object>;
    /**
     * Ignores discovery service with given service ids.
     */
    discoveryIgnoreRaw(requestParameters: DiscoveryIgnoreRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>>;
    /**
     * Ignores discovery service with given service ids.
     */
    discoveryIgnore(requestParameters: DiscoveryIgnoreRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string>;
    /**
     * Ignores discovery services for selected filters.
     */
    discoveryIgnoreByFilterRaw(requestParameters: DiscoveryIgnoreByFilterRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>>;
    /**
     * Ignores discovery services for selected filters.
     */
    discoveryIgnoreByFilter(requestParameters?: DiscoveryIgnoreByFilterRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string>;
    /**
     * Gets the list discovery services.
     */
    discoveryListRaw(requestParameters: DiscoveryListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<DiscoveryServiceListApiResult>>;
    /**
     * Gets the list discovery services.
     */
    discoveryList(requestParameters?: DiscoveryListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<DiscoveryServiceListApiResult>;
    /**
     * Gets the list discovery services with filter.
     */
    discoveryListByFilterRaw(requestParameters: DiscoveryListByFilterRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<DiscoveryServiceListApiResult>>;
    /**
     * Gets the list discovery services with filter.
     */
    discoveryListByFilter(requestParameters?: DiscoveryListByFilterRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<DiscoveryServiceListApiResult>;
    /**
     * Gets the discovery settings.
     */
    discoverySettingsRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<DiscoverySettingsApiModel>>;
    /**
     * Gets the discovery settings.
     */
    discoverySettings(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<DiscoverySettingsApiModel>;
    /**
     * Updates discovery settings.
     */
    discoveryUpdateSettingsRaw(requestParameters: DiscoveryUpdateSettingsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<DiscoverySettingsApiModel>>;
    /**
     * Updates discovery settings.
     */
    discoveryUpdateSettings(requestParameters: DiscoveryUpdateSettingsRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<DiscoverySettingsApiModel>;
}
/**
 * @export
 */
export declare const DiscoveryConnectionByIdTypeEnum: {
    readonly Aws: "Aws";
};
export type DiscoveryConnectionByIdTypeEnum = typeof DiscoveryConnectionByIdTypeEnum[keyof typeof DiscoveryConnectionByIdTypeEnum];
/**
 * @export
 */
export declare const DiscoveryConnectionsTypeEnum: {
    readonly Aws: "Aws";
};
export type DiscoveryConnectionsTypeEnum = typeof DiscoveryConnectionsTypeEnum[keyof typeof DiscoveryConnectionsTypeEnum];
/**
 * @export
 */
export declare const DiscoveryExportCsvSeparatorEnum: {
    readonly Comma: "Comma";
    readonly Semicolon: "Semicolon";
    readonly Pipe: "Pipe";
    readonly Tab: "Tab";
};
export type DiscoveryExportCsvSeparatorEnum = typeof DiscoveryExportCsvSeparatorEnum[keyof typeof DiscoveryExportCsvSeparatorEnum];
/**
 * @export
 */
export declare const DiscoveryListByFilterStatusEnum: {
    readonly Discovered: "Discovered";
    readonly Ignored: "Ignored";
    readonly Created: "Created";
};
export type DiscoveryListByFilterStatusEnum = typeof DiscoveryListByFilterStatusEnum[keyof typeof DiscoveryListByFilterStatusEnum];
