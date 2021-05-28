/**
 * Netsparker Enterprise API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
/// <reference types="node" />
import http from 'http';
import { DeleteWebsiteGroupApiModel } from '../model/deleteWebsiteGroupApiModel';
import { NewWebsiteGroupApiModel } from '../model/newWebsiteGroupApiModel';
import { UpdateWebsiteGroupApiModel } from '../model/updateWebsiteGroupApiModel';
import { WebsiteGroupApiModel } from '../model/websiteGroupApiModel';
import { WebsiteGroupListApiResult } from '../model/websiteGroupListApiResult';
import { Authentication, Interceptor } from '../model/models';
export declare enum WebsiteGroupsApiApiKeys {
}
export declare class WebsiteGroupsApi {
    protected _basePath: string;
    protected _defaultHeaders: any;
    protected _useQuerystring: boolean;
    protected authentications: {
        default: Authentication;
    };
    protected interceptors: Interceptor[];
    constructor(basePath?: string);
    set useQuerystring(value: boolean);
    set basePath(basePath: string);
    set defaultHeaders(defaultHeaders: any);
    get defaultHeaders(): any;
    get basePath(): string;
    setDefaultAuthentication(auth: Authentication): void;
    setApiKey(key: WebsiteGroupsApiApiKeys, value: string): void;
    addInterceptor(interceptor: Interceptor): void;
    /**
     *
     * @summary Deletes a website group.
     * @param model The model.
     */
    websiteGroupsDelete(model: DeleteWebsiteGroupApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: string;
    }>;
    /**
     *
     * @summary Deletes a website group with given id
     * @param id website group id
     */
    websiteGroupsDelete_1(id: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: string;
    }>;
    /**
     *
     * @summary Gets website group by name.
     * @param query name.
     */
    websiteGroupsGet(query: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: WebsiteGroupApiModel;
    }>;
    /**
     *
     * @summary Gets website group by id.
     * @param id id.
     */
    websiteGroupsGet_2(id: string, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: WebsiteGroupApiModel;
    }>;
    /**
     *
     * @summary Gets the list of website groups.
     * @param page The page size.
     * @param pageSize The page size. Page size can be any value between 1 and 200.
     */
    websiteGroupsList(page?: number, pageSize?: number, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: WebsiteGroupListApiResult;
    }>;
    /**
     *
     * @summary Creates a new website group.
     * @param model The model.
     */
    websiteGroupsNew(model: NewWebsiteGroupApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: WebsiteGroupApiModel;
    }>;
    /**
     *
     * @summary Updates a website group.
     * @param model The model.
     */
    websiteGroupsUpdate(model: UpdateWebsiteGroupApiModel, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: WebsiteGroupApiModel;
    }>;
}