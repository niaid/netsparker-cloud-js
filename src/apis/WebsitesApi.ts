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
  DeleteWebsiteApiModel,
  NewWebsiteApiModel,
  SendVerificationEmailModel,
  StartVerificationApiModel,
  StartVerificationResult,
  UpdateWebsiteApiModel,
  VerifyApiModel,
  WebsiteApiModel,
  WebsiteListApiResult,
} from '../models/index';
import {
    DeleteWebsiteApiModelFromJSON,
    DeleteWebsiteApiModelToJSON,
    NewWebsiteApiModelFromJSON,
    NewWebsiteApiModelToJSON,
    SendVerificationEmailModelFromJSON,
    SendVerificationEmailModelToJSON,
    StartVerificationApiModelFromJSON,
    StartVerificationApiModelToJSON,
    StartVerificationResultFromJSON,
    StartVerificationResultToJSON,
    UpdateWebsiteApiModelFromJSON,
    UpdateWebsiteApiModelToJSON,
    VerifyApiModelFromJSON,
    VerifyApiModelToJSON,
    WebsiteApiModelFromJSON,
    WebsiteApiModelToJSON,
    WebsiteListApiResultFromJSON,
    WebsiteListApiResultToJSON,
} from '../models/index';

export interface WebsitesApiWebsitesDeleteRequest {
    model: DeleteWebsiteApiModel;
}

export interface WebsitesApiWebsitesGetByIdRequest {
    id: string;
}

export interface WebsitesApiWebsitesGetByQueryRequest {
    query: string;
}

export interface WebsitesApiWebsitesGetWebsitesByGroupRequest {
    query: string;
    page?: number;
    pageSize?: number;
}

export interface WebsitesApiWebsitesListRequest {
    page?: number;
    pageSize?: number;
}

export interface WebsitesApiWebsitesNewRequest {
    model: NewWebsiteApiModel;
}

export interface WebsitesApiWebsitesSendVerificationEmailRequest {
    websiteUrl: string;
}

export interface WebsitesApiWebsitesStartVerificationRequest {
    model: StartVerificationApiModel;
}

export interface WebsitesApiWebsitesUpdateRequest {
    model: UpdateWebsiteApiModel;
}

export interface WebsitesApiWebsitesVerificationFileRequest {
    websiteUrl: string;
}

export interface WebsitesApiWebsitesVerifyRequest {
    model: VerifyApiModel;
}

/**
 * 
 */
export class WebsitesApi extends runtime.BaseAPI {

    /**
     * Deletes a website.
     */
    async websitesDeleteRaw(requestParameters: WebsitesApiWebsitesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling websitesDelete.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/websites/delete`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: DeleteWebsiteApiModelToJSON(requestParameters.model),
        }, initOverrides);

        if (this.isJsonMime(response.headers.get('content-type'))) {
            return new runtime.JSONApiResponse<string>(response);
        } else {
            return new runtime.TextApiResponse(response) as any;
        }
    }

    /**
     * Deletes a website.
     */
    async websitesDelete(requestParameters: WebsitesApiWebsitesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string> {
        const response = await this.websitesDeleteRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets website by id.
     */
    async websitesGetByIdRaw(requestParameters: WebsitesApiWebsitesGetByIdRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteApiModel>> {
        if (requestParameters.id === null || requestParameters.id === undefined) {
            throw new runtime.RequiredError('id','Required parameter requestParameters.id was null or undefined when calling websitesGetById.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/websites/get/{id}`.replace(`{${"id"}}`, encodeURIComponent(String(requestParameters.id))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => WebsiteApiModelFromJSON(jsonValue));
    }

    /**
     * Gets website by id.
     */
    async websitesGetById(requestParameters: WebsitesApiWebsitesGetByIdRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteApiModel> {
        const response = await this.websitesGetByIdRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets website by name or URL.
     */
    async websitesGetByQueryRaw(requestParameters: WebsitesApiWebsitesGetByQueryRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteApiModel>> {
        if (requestParameters.query === null || requestParameters.query === undefined) {
            throw new runtime.RequiredError('query','Required parameter requestParameters.query was null or undefined when calling websitesGetByQuery.');
        }

        const queryParameters: any = {};

        if (requestParameters.query !== undefined) {
            queryParameters['query'] = requestParameters.query;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/websites/get`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => WebsiteApiModelFromJSON(jsonValue));
    }

    /**
     * Gets website by name or URL.
     */
    async websitesGetByQuery(requestParameters: WebsitesApiWebsitesGetByQueryRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteApiModel> {
        const response = await this.websitesGetByQueryRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the list of websites by group name or id.
     */
    async websitesGetWebsitesByGroupRaw(requestParameters: WebsitesApiWebsitesGetWebsitesByGroupRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteListApiResult>> {
        if (requestParameters.query === null || requestParameters.query === undefined) {
            throw new runtime.RequiredError('query','Required parameter requestParameters.query was null or undefined when calling websitesGetWebsitesByGroup.');
        }

        const queryParameters: any = {};

        if (requestParameters.query !== undefined) {
            queryParameters['query'] = requestParameters.query;
        }

        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }

        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/websites/getwebsitesbygroup`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => WebsiteListApiResultFromJSON(jsonValue));
    }

    /**
     * Gets the list of websites by group name or id.
     */
    async websitesGetWebsitesByGroup(requestParameters: WebsitesApiWebsitesGetWebsitesByGroupRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteListApiResult> {
        const response = await this.websitesGetWebsitesByGroupRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the list of websites.
     */
    async websitesListRaw(requestParameters: WebsitesApiWebsitesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteListApiResult>> {
        const queryParameters: any = {};

        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }

        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/websites/list`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => WebsiteListApiResultFromJSON(jsonValue));
    }

    /**
     * Gets the list of websites.
     */
    async websitesList(requestParameters: WebsitesApiWebsitesListRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteListApiResult> {
        const response = await this.websitesListRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Creates a new website.
     */
    async websitesNewRaw(requestParameters: WebsitesApiWebsitesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteApiModel>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling websitesNew.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/websites/new`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: NewWebsiteApiModelToJSON(requestParameters.model),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => WebsiteApiModelFromJSON(jsonValue));
    }

    /**
     * Creates a new website.
     */
    async websitesNew(requestParameters: WebsitesApiWebsitesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteApiModel> {
        const response = await this.websitesNewRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Sends the verification email if verification limit not exceeded yet.
     */
    async websitesSendVerificationEmailRaw(requestParameters: WebsitesApiWebsitesSendVerificationEmailRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<SendVerificationEmailModel>> {
        if (requestParameters.websiteUrl === null || requestParameters.websiteUrl === undefined) {
            throw new runtime.RequiredError('websiteUrl','Required parameter requestParameters.websiteUrl was null or undefined when calling websitesSendVerificationEmail.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/websites/sendverificationemail`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: requestParameters.websiteUrl as any,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => SendVerificationEmailModelFromJSON(jsonValue));
    }

    /**
     * Sends the verification email if verification limit not exceeded yet.
     */
    async websitesSendVerificationEmail(requestParameters: WebsitesApiWebsitesSendVerificationEmailRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<SendVerificationEmailModel> {
        const response = await this.websitesSendVerificationEmailRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Starts the verification with specified method.
     */
    async websitesStartVerificationRaw(requestParameters: WebsitesApiWebsitesStartVerificationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<StartVerificationResult>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling websitesStartVerification.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/websites/startverification`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: StartVerificationApiModelToJSON(requestParameters.model),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => StartVerificationResultFromJSON(jsonValue));
    }

    /**
     * Starts the verification with specified method.
     */
    async websitesStartVerification(requestParameters: WebsitesApiWebsitesStartVerificationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<StartVerificationResult> {
        const response = await this.websitesStartVerificationRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Updates a website.
     */
    async websitesUpdateRaw(requestParameters: WebsitesApiWebsitesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteApiModel>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling websitesUpdate.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/websites/update`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: UpdateWebsiteApiModelToJSON(requestParameters.model),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => WebsiteApiModelFromJSON(jsonValue));
    }

    /**
     * Updates a website.
     */
    async websitesUpdate(requestParameters: WebsitesApiWebsitesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteApiModel> {
        const response = await this.websitesUpdateRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Renders verification file.
     */
    async websitesVerificationFileRaw(requestParameters: WebsitesApiWebsitesVerificationFileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.websiteUrl === null || requestParameters.websiteUrl === undefined) {
            throw new runtime.RequiredError('websiteUrl','Required parameter requestParameters.websiteUrl was null or undefined when calling websitesVerificationFile.');
        }

        const queryParameters: any = {};

        if (requestParameters.websiteUrl !== undefined) {
            queryParameters['websiteUrl'] = requestParameters.websiteUrl;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/websites/verificationfile`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Renders verification file.
     */
    async websitesVerificationFile(requestParameters: WebsitesApiWebsitesVerificationFileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.websitesVerificationFileRaw(requestParameters, initOverrides);
    }

    /**
     * Executes verification process.
     */
    async websitesVerifyRaw(requestParameters: WebsitesApiWebsitesVerifyRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling websitesVerify.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/websites/verify`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: VerifyApiModelToJSON(requestParameters.model),
        }, initOverrides);

        if (this.isJsonMime(response.headers.get('content-type'))) {
            return new runtime.JSONApiResponse<string>(response);
        } else {
            return new runtime.TextApiResponse(response) as any;
        }
    }

    /**
     * Executes verification process.
     */
    async websitesVerify(requestParameters: WebsitesApiWebsitesVerifyRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string> {
        const response = await this.websitesVerifyRaw(requestParameters, initOverrides);
        return await response.value();
    }

}
