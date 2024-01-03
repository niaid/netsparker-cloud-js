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
  NewScanPolicySettingModel,
  ScanPolicyListApiResult,
  ScanPolicySettingApiModel,
  UpdateScanPolicySettingModel,
} from '../models/index';
import {
    NewScanPolicySettingModelFromJSON,
    NewScanPolicySettingModelToJSON,
    ScanPolicyListApiResultFromJSON,
    ScanPolicyListApiResultToJSON,
    ScanPolicySettingApiModelFromJSON,
    ScanPolicySettingApiModelToJSON,
    UpdateScanPolicySettingModelFromJSON,
    UpdateScanPolicySettingModelToJSON,
} from '../models/index';

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
export class ScanPoliciesApi extends runtime.BaseAPI {

    /**
     * Deletes a scan policy.
     */
    async scanPoliciesDeleteRaw(requestParameters: ScanPoliciesApiScanPoliciesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.name === null || requestParameters.name === undefined) {
            throw new runtime.RequiredError('name','Required parameter requestParameters.name was null or undefined when calling scanPoliciesDelete.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/scanpolicies/delete`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: requestParameters.name as any,
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Deletes a scan policy.
     */
    async scanPoliciesDelete(requestParameters: ScanPoliciesApiScanPoliciesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.scanPoliciesDeleteRaw(requestParameters, initOverrides);
    }

    /**
     * Gets the scan policy by the specified name.
     */
    async scanPoliciesFindRaw(requestParameters: ScanPoliciesApiScanPoliciesFindRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>> {
        if (requestParameters.name === null || requestParameters.name === undefined) {
            throw new runtime.RequiredError('name','Required parameter requestParameters.name was null or undefined when calling scanPoliciesFind.');
        }

        const queryParameters: any = {};

        if (requestParameters.name !== undefined) {
            queryParameters['name'] = requestParameters.name;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/scanpolicies/get`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => ScanPolicySettingApiModelFromJSON(jsonValue));
    }

    /**
     * Gets the scan policy by the specified name.
     */
    async scanPoliciesFind(requestParameters: ScanPoliciesApiScanPoliciesFindRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel> {
        const response = await this.scanPoliciesFindRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the scan policy by the specified id.
     */
    async scanPoliciesGetRaw(requestParameters: ScanPoliciesApiScanPoliciesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>> {
        if (requestParameters.id === null || requestParameters.id === undefined) {
            throw new runtime.RequiredError('id','Required parameter requestParameters.id was null or undefined when calling scanPoliciesGet.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/scanpolicies/get/{id}`.replace(`{${"id"}}`, encodeURIComponent(String(requestParameters.id))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => ScanPolicySettingApiModelFromJSON(jsonValue));
    }

    /**
     * Gets the scan policy by the specified id.
     */
    async scanPoliciesGet(requestParameters: ScanPoliciesApiScanPoliciesGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel> {
        const response = await this.scanPoliciesGetRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the list of scan policies.
     */
    async scanPoliciesListRaw(requestParameters: ScanPoliciesApiScanPoliciesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicyListApiResult>> {
        const queryParameters: any = {};

        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }

        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/scanpolicies/list`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => ScanPolicyListApiResultFromJSON(jsonValue));
    }

    /**
     * Gets the list of scan policies.
     */
    async scanPoliciesList(requestParameters: ScanPoliciesApiScanPoliciesListRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicyListApiResult> {
        const response = await this.scanPoliciesListRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Creates a new scan policy.
     */
    async scanPoliciesNewRaw(requestParameters: ScanPoliciesApiScanPoliciesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling scanPoliciesNew.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/scanpolicies/new`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: NewScanPolicySettingModelToJSON(requestParameters.model),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => ScanPolicySettingApiModelFromJSON(jsonValue));
    }

    /**
     * Creates a new scan policy.
     */
    async scanPoliciesNew(requestParameters: ScanPoliciesApiScanPoliciesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel> {
        const response = await this.scanPoliciesNewRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Updates a scan policy.
     */
    async scanPoliciesUpdateRaw(requestParameters: ScanPoliciesApiScanPoliciesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<ScanPolicySettingApiModel>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling scanPoliciesUpdate.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/scanpolicies/update`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: UpdateScanPolicySettingModelToJSON(requestParameters.model),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => ScanPolicySettingApiModelFromJSON(jsonValue));
    }

    /**
     * Updates a scan policy.
     */
    async scanPoliciesUpdate(requestParameters: ScanPoliciesApiScanPoliciesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<ScanPolicySettingApiModel> {
        const response = await this.scanPoliciesUpdateRaw(requestParameters, initOverrides);
        return await response.value();
    }

}
