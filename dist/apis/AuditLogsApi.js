"use strict";
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
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditLogsExportCsvSeparatorEnum = exports.AuditLogsApi = void 0;
const runtime = __importStar(require("../runtime"));
/**
 *
 */
class AuditLogsApi extends runtime.BaseAPI {
    /**
     * Returns the selected log type in the csv format as a downloadable file.
     */
    async auditLogsExportRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }
        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }
        if (requestParameters.csvSeparator !== undefined) {
            queryParameters['csvSeparator'] = requestParameters.csvSeparator;
        }
        if (requestParameters.startDate !== undefined) {
            queryParameters['startDate'] = requestParameters.startDate.toISOString();
        }
        if (requestParameters.endDate !== undefined) {
            queryParameters['endDate'] = requestParameters.endDate.toISOString();
        }
        const headerParameters = {};
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
    async auditLogsExport(requestParameters = {}, initOverrides) {
        await this.auditLogsExportRaw(requestParameters, initOverrides);
    }
    /**
     * Gets the list of audit logs.
     */
    async auditLogsListRaw(requestParameters, initOverrides) {
        const queryParameters = {};
        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }
        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }
        if (requestParameters.startDate !== undefined) {
            queryParameters['startDate'] = requestParameters.startDate.toISOString();
        }
        if (requestParameters.endDate !== undefined) {
            queryParameters['endDate'] = requestParameters.endDate.toISOString();
        }
        const headerParameters = {};
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
    async auditLogsList(requestParameters = {}, initOverrides) {
        await this.auditLogsListRaw(requestParameters, initOverrides);
    }
}
exports.AuditLogsApi = AuditLogsApi;
/**
  * @export
  * @enum {string}
  */
var AuditLogsExportCsvSeparatorEnum;
(function (AuditLogsExportCsvSeparatorEnum) {
    AuditLogsExportCsvSeparatorEnum["Comma"] = "Comma";
    AuditLogsExportCsvSeparatorEnum["Semicolon"] = "Semicolon";
    AuditLogsExportCsvSeparatorEnum["Pipe"] = "Pipe";
    AuditLogsExportCsvSeparatorEnum["Tab"] = "Tab";
})(AuditLogsExportCsvSeparatorEnum = exports.AuditLogsExportCsvSeparatorEnum || (exports.AuditLogsExportCsvSeparatorEnum = {}));
//# sourceMappingURL=AuditLogsApi.js.map