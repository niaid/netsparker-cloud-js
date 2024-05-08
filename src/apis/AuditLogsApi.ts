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

export interface AuditLogsExportRequest {
    page?: number;
    pageSize?: number;
    csvSeparator?: AuditLogsExportCsvSeparatorEnum;
    startDate?: Date;
    endDate?: Date;
}

export interface AuditLogsListRequest {
    page?: number;
    pageSize?: number;
    startDate?: Date;
    endDate?: Date;
}

/**
 * 
 */
export class AuditLogsApi extends runtime.BaseAPI {

    /**
     * Returns the selected log type in the csv format as a downloadable file.
     */
    async auditLogsExportRaw(requestParameters: AuditLogsExportRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        const queryParameters: any = {};

        if (requestParameters['page'] != null) {
            queryParameters['page'] = requestParameters['page'];
        }

        if (requestParameters['pageSize'] != null) {
            queryParameters['pageSize'] = requestParameters['pageSize'];
        }

        if (requestParameters['csvSeparator'] != null) {
            queryParameters['csvSeparator'] = requestParameters['csvSeparator'];
        }

        if (requestParameters['startDate'] != null) {
            queryParameters['startDate'] = (requestParameters['startDate'] as any).toISOString();
        }

        if (requestParameters['endDate'] != null) {
            queryParameters['endDate'] = (requestParameters['endDate'] as any).toISOString();
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/auditlogs/export`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Returns the selected log type in the csv format as a downloadable file.
     */
    async auditLogsExport(requestParameters: AuditLogsExportRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.auditLogsExportRaw(requestParameters, initOverrides);
    }

    /**
     * Gets the list of audit logs.
     */
    async auditLogsListRaw(requestParameters: AuditLogsListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        const queryParameters: any = {};

        if (requestParameters['page'] != null) {
            queryParameters['page'] = requestParameters['page'];
        }

        if (requestParameters['pageSize'] != null) {
            queryParameters['pageSize'] = requestParameters['pageSize'];
        }

        if (requestParameters['startDate'] != null) {
            queryParameters['startDate'] = (requestParameters['startDate'] as any).toISOString();
        }

        if (requestParameters['endDate'] != null) {
            queryParameters['endDate'] = (requestParameters['endDate'] as any).toISOString();
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/auditlogs/list`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Gets the list of audit logs.
     */
    async auditLogsList(requestParameters: AuditLogsListRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.auditLogsListRaw(requestParameters, initOverrides);
    }

}

/**
 * @export
 */
export const AuditLogsExportCsvSeparatorEnum = {
    Comma: 'Comma',
    Semicolon: 'Semicolon',
    Pipe: 'Pipe',
    Tab: 'Tab'
} as const;
export type AuditLogsExportCsvSeparatorEnum = typeof AuditLogsExportCsvSeparatorEnum[keyof typeof AuditLogsExportCsvSeparatorEnum];
