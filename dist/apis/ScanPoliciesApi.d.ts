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
import type { NewScanPolicySettingModel, ScanPolicyListApiResult, ScanPolicySettingApiModel, UpdateScanPolicySettingModel } from '../models/index';
export interface ScanPoliciesApiScanPoliciesDeleteRequest {
    name: string;
}
export interface ScanPoliciesApiScanPoliciesFindRequest {
    name: string;
}
export interface ScanPoliciesApiScanPoliciesGetRequest {
    id: string;
}
export interface ScanPoliciesApiScanPoliciesListRequest {
    page?: number;
    pageSize?: number;
}
export interface ScanPoliciesApiScanPoliciesNewRequest {
    model: NewScanPolicySettingModel;
}
export interface ScanPoliciesApiScanPoliciesUpdateRequest {
    model: UpdateScanPolicySettingModel;
}
/**
 *
 */
export declare class ScanPoliciesApi extends runtime.BaseAPI {
    /**
     * Deletes a scan policy.
     */
    scanPoliciesDeleteRaw(requestParameters: ScanPoliciesApiScanPoliciesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Deletes a scan policy.
     */
    scanPoliciesDelete(requestParameters: ScanPoliciesApiScanPoliciesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Gets the scan policy by the specified name.
     */
    scanPoliciesFindRaw(requestParameters: ScanPoliciesApiScanPoliciesFindRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>>;
    /**
     * Gets the scan policy by the specified name.
     */
    scanPoliciesFind(requestParameters: ScanPoliciesApiScanPoliciesFindRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel>;
    /**
     * Gets the scan policy by the specified id.
     */
    scanPoliciesGetRaw(requestParameters: ScanPoliciesApiScanPoliciesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>>;
    /**
     * Gets the scan policy by the specified id.
     */
    scanPoliciesGet(requestParameters: ScanPoliciesApiScanPoliciesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel>;
    /**
     * Gets the list of scan policies.
     */
    scanPoliciesListRaw(requestParameters: ScanPoliciesApiScanPoliciesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicyListApiResult>>;
    /**
     * Gets the list of scan policies.
     */
    scanPoliciesList(requestParameters?: ScanPoliciesApiScanPoliciesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicyListApiResult>;
    /**
     * Creates a new scan policy.
     */
    scanPoliciesNewRaw(requestParameters: ScanPoliciesApiScanPoliciesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>>;
    /**
     * Creates a new scan policy.
     */
    scanPoliciesNew(requestParameters: ScanPoliciesApiScanPoliciesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel>;
    /**
     * Updates a scan policy.
     */
    scanPoliciesUpdateRaw(requestParameters: ScanPoliciesApiScanPoliciesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>>;
    /**
     * Updates a scan policy.
     */
    scanPoliciesUpdate(requestParameters: ScanPoliciesApiScanPoliciesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel>;
}
