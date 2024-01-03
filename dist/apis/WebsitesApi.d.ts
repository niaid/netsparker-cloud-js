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
import type { DeleteWebsiteApiModel, NewWebsiteApiModel, SendVerificationEmailModel, StartVerificationApiModel, StartVerificationResult, UpdateWebsiteApiModel, VerifyApiModel, WebsiteApiModel, WebsiteListApiResult } from '../models/index';
export interface WebsitesDeleteRequest {
    model: DeleteWebsiteApiModel;
}
export interface WebsitesGetByIdRequest {
    id: string;
}
export interface WebsitesGetByQueryRequest {
    query: string;
}
export interface WebsitesGetWebsitesByGroupRequest {
    query: string;
    page?: number;
    pageSize?: number;
}
export interface WebsitesListRequest {
    page?: number;
    pageSize?: number;
}
export interface WebsitesNewRequest {
    model: NewWebsiteApiModel;
}
export interface WebsitesSendVerificationEmailRequest {
    websiteUrl: string;
}
export interface WebsitesStartVerificationRequest {
    model: StartVerificationApiModel;
}
export interface WebsitesUpdateRequest {
    model: UpdateWebsiteApiModel;
}
export interface WebsitesVerificationFileRequest {
    websiteUrl: string;
}
export interface WebsitesVerifyRequest {
    model: VerifyApiModel;
}
/**
 *
 */
export declare class WebsitesApi extends runtime.BaseAPI {
    /**
     * Deletes a website.
     */
    websitesDeleteRaw(requestParameters: WebsitesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>>;
    /**
     * Deletes a website.
     */
    websitesDelete(requestParameters: WebsitesDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string>;
    /**
     * Gets website by id.
     */
    websitesGetByIdRaw(requestParameters: WebsitesGetByIdRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteApiModel>>;
    /**
     * Gets website by id.
     */
    websitesGetById(requestParameters: WebsitesGetByIdRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteApiModel>;
    /**
     * Gets website by name or URL.
     */
    websitesGetByQueryRaw(requestParameters: WebsitesGetByQueryRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteApiModel>>;
    /**
     * Gets website by name or URL.
     */
    websitesGetByQuery(requestParameters: WebsitesGetByQueryRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteApiModel>;
    /**
     * Gets the list of websites by group name or id.
     */
    websitesGetWebsitesByGroupRaw(requestParameters: WebsitesGetWebsitesByGroupRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteListApiResult>>;
    /**
     * Gets the list of websites by group name or id.
     */
    websitesGetWebsitesByGroup(requestParameters: WebsitesGetWebsitesByGroupRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteListApiResult>;
    /**
     * Gets the list of websites.
     */
    websitesListRaw(requestParameters: WebsitesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteListApiResult>>;
    /**
     * Gets the list of websites.
     */
    websitesList(requestParameters?: WebsitesListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteListApiResult>;
    /**
     * Creates a new website.
     */
    websitesNewRaw(requestParameters: WebsitesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteApiModel>>;
    /**
     * Creates a new website.
     */
    websitesNew(requestParameters: WebsitesNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteApiModel>;
    /**
     * Sends the verification email if verification limit not exceeded yet.
     */
    websitesSendVerificationEmailRaw(requestParameters: WebsitesSendVerificationEmailRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<SendVerificationEmailModel>>;
    /**
     * Sends the verification email if verification limit not exceeded yet.
     */
    websitesSendVerificationEmail(requestParameters: WebsitesSendVerificationEmailRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<SendVerificationEmailModel>;
    /**
     * Starts the verification with specified method.
     */
    websitesStartVerificationRaw(requestParameters: WebsitesStartVerificationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<StartVerificationResult>>;
    /**
     * Starts the verification with specified method.
     */
    websitesStartVerification(requestParameters: WebsitesStartVerificationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<StartVerificationResult>;
    /**
     * Updates a website.
     */
    websitesUpdateRaw(requestParameters: WebsitesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<WebsiteApiModel>>;
    /**
     * Updates a website.
     */
    websitesUpdate(requestParameters: WebsitesUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<WebsiteApiModel>;
    /**
     * Renders verification file.
     */
    websitesVerificationFileRaw(requestParameters: WebsitesVerificationFileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>>;
    /**
     * Renders verification file.
     */
    websitesVerificationFile(requestParameters: WebsitesVerificationFileRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void>;
    /**
     * Executes verification process.
     */
    websitesVerifyRaw(requestParameters: WebsitesVerifyRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>>;
    /**
     * Executes verification process.
     */
    websitesVerify(requestParameters: WebsitesVerifyRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string>;
}