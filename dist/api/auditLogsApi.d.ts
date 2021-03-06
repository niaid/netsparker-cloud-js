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
import { Authentication, Interceptor } from '../model/models';
export declare enum AuditLogsApiApiKeys {
}
export declare class AuditLogsApi {
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
    setApiKey(key: AuditLogsApiApiKeys, value: string): void;
    addInterceptor(interceptor: Interceptor): void;
    /**
     *
     * @summary Returns the selected log type in the csv format as a downloadable file.
     * @param page The page. Default : 1.
     * @param pageSize The page size. Default : 200.
     * @param csvSeparator The csv separator. Default comma (,)
     * @param startDate The start date is used for logs and it is less than or equal to Date field.Format: MM/dd/yyyy 00:00:00
     * @param endDate The end date is used for logs and it is greather than or equal to Date field.Format: MM/dd/yyyy 23:59:59
     */
    auditLogsExport(page?: number, pageSize?: number, csvSeparator?: 'Comma' | 'Semicolon' | 'Pipe' | 'Tab', startDate?: Date, endDate?: Date, options?: {
        headers: {
            [name: string]: string;
        };
    }): Promise<{
        response: http.IncomingMessage;
        body?: any;
    }>;
}
