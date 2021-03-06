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
import { AccountLicenseApiModel } from '../model/accountLicenseApiModel';
import { UserHealthCheckApiModel } from '../model/userHealthCheckApiModel';
import { Authentication, Interceptor } from '../model/models';
export declare enum AccountApiApiKeys {
}
export declare class AccountApi {
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
    setApiKey(key: AccountApiApiKeys, value: string): void;
    addInterceptor(interceptor: Interceptor): void;
    /**
     *
     * @summary Gives user\'s account license.
     */
    accountLicense(options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: AccountLicenseApiModel;
    }>;
    /**
     *
     * @summary Gets the information of callee
     */
    accountMe(options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body: UserHealthCheckApiModel;
    }>;
}
