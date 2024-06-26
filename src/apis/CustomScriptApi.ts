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
  CustomScriptRequestApiModel,
  CustomScriptUpdateRequestApiModel,
} from '../models/index';
import {
    CustomScriptRequestApiModelFromJSON,
    CustomScriptRequestApiModelToJSON,
    CustomScriptUpdateRequestApiModelFromJSON,
    CustomScriptUpdateRequestApiModelToJSON,
} from '../models/index';

export interface CustomScriptDeleteRequest {
    ids: Array<string>;
}

export interface CustomScriptNewRequest {
    model: Array<CustomScriptRequestApiModel>;
}

export interface CustomScriptUpdateRequest {
    model: Array<CustomScriptUpdateRequestApiModel>;
}

/**
 * 
 */
export class CustomScriptApi extends runtime.BaseAPI {

    /**
     * Deletes Custom Scripts
     */
    async customScriptDeleteRaw(requestParameters: CustomScriptDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>> {
        if (requestParameters['ids'] == null) {
            throw new runtime.RequiredError(
                'ids',
                'Required parameter "ids" was null or undefined when calling customScriptDelete().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/customscript/delete`,
            method: 'DELETE',
            headers: headerParameters,
            query: queryParameters,
            body: requestParameters['ids'],
        }, initOverrides);

        return new runtime.JSONApiResponse<any>(response);
    }

    /**
     * Deletes Custom Scripts
     */
    async customScriptDelete(requestParameters: CustomScriptDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object> {
        const response = await this.customScriptDeleteRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Lists Custom Scripts
     */
    async customScriptListRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>> {
        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/customscript/list`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse<any>(response);
    }

    /**
     * Lists Custom Scripts
     */
    async customScriptList(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object> {
        const response = await this.customScriptListRaw(initOverrides);
        return await response.value();
    }

    /**
     * Creates Custom Scripts
     */
    async customScriptNewRaw(requestParameters: CustomScriptNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>> {
        if (requestParameters['model'] == null) {
            throw new runtime.RequiredError(
                'model',
                'Required parameter "model" was null or undefined when calling customScriptNew().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/customscript/new`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: requestParameters['model']!.map(CustomScriptRequestApiModelToJSON),
        }, initOverrides);

        return new runtime.JSONApiResponse<any>(response);
    }

    /**
     * Creates Custom Scripts
     */
    async customScriptNew(requestParameters: CustomScriptNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object> {
        const response = await this.customScriptNewRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Updates Custom Scripts
     */
    async customScriptUpdateRaw(requestParameters: CustomScriptUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<object>> {
        if (requestParameters['model'] == null) {
            throw new runtime.RequiredError(
                'model',
                'Required parameter "model" was null or undefined when calling customScriptUpdate().'
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/customscript/update`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: requestParameters['model']!.map(CustomScriptUpdateRequestApiModelToJSON),
        }, initOverrides);

        return new runtime.JSONApiResponse<any>(response);
    }

    /**
     * Updates Custom Scripts
     */
    async customScriptUpdate(requestParameters: CustomScriptUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<object> {
        const response = await this.customScriptUpdateRaw(requestParameters, initOverrides);
        return await response.value();
    }

}
