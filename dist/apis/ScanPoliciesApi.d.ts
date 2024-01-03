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
export interface ScanPoliciesDeleteRequest {
    name: string;
}
export interface ScanPoliciesFindRequest {
    name: string;
}
export interface ScanPoliciesGetRequest {
    id: string;
}
export interface ScanPoliciesListRequest {
    page?: number;
    pageSize?: number;
}
export interface ScanPoliciesNewRequest {
    model: NewScanPolicySettingModel;
}
export interface ScanPoliciesUpdateRequest {
    model: UpdateScanPolicySettingModel;
}
/**
 *
 */
export declare class ScanPoliciesApi extends runtime.BaseAPI {
    /**
     * Deletes a scan policy.
     */
    scanPoliciesDeleteRaw(requestParameters: ScanPoliciesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Deletes a scan policy.
     */
    scanPoliciesDelete(requestParameters: ScanPoliciesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Gets the scan policy by the specified name.
     */
    scanPoliciesFindRaw(requestParameters: ScanPoliciesFindRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>>;
    /**
     * Gets the scan policy by the specified name.
     */
    scanPoliciesFind(requestParameters: ScanPoliciesFindRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel>;
    /**
     * Gets the scan policy by the specified id.
     */
    scanPoliciesGetRaw(requestParameters: ScanPoliciesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>>;
    /**
     * Gets the scan policy by the specified id.
     */
    scanPoliciesGet(requestParameters: ScanPoliciesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel>;
    /**
     * Gets the list of scan policies.
     */
    scanPoliciesListRaw(requestParameters: ScanPoliciesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicyListApiResult>>;
    /**
     * Gets the list of scan policies.
     */
    scanPoliciesList(requestParameters?: ScanPoliciesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicyListApiResult>;
    /**
     * Creates a new scan policy.
     */
    scanPoliciesNewRaw(requestParameters: ScanPoliciesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>>;
    /**
     * Creates a new scan policy.
     */
    scanPoliciesNew(requestParameters: ScanPoliciesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel>;
    /**
     * Updates a scan policy.
     */
    scanPoliciesUpdateRaw(requestParameters: ScanPoliciesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>>;
    /**
     * Updates a scan policy.
     */
    scanPoliciesUpdate(requestParameters: ScanPoliciesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel>;
}