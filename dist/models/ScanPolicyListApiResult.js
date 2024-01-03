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
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScanPolicyListApiResultToJSON = exports.ScanPolicyListApiResultFromJSONTyped = exports.ScanPolicyListApiResultFromJSON = exports.instanceOfScanPolicyListApiResult = void 0;
const runtime_1 = require("../runtime");
const ScanPolicySettingItemApiModel_1 = require("./ScanPolicySettingItemApiModel");
/**
 * Check if a given object implements the ScanPolicyListApiResult interface.
 */
function instanceOfScanPolicyListApiResult(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfScanPolicyListApiResult = instanceOfScanPolicyListApiResult;
function ScanPolicyListApiResultFromJSON(json) {
    return ScanPolicyListApiResultFromJSONTyped(json, false);
}
exports.ScanPolicyListApiResultFromJSON = ScanPolicyListApiResultFromJSON;
function ScanPolicyListApiResultFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'firstItemOnPage': !(0, runtime_1.exists)(json, 'FirstItemOnPage') ? undefined : json['FirstItemOnPage'],
        'hasNextPage': !(0, runtime_1.exists)(json, 'HasNextPage') ? undefined : json['HasNextPage'],
        'hasPreviousPage': !(0, runtime_1.exists)(json, 'HasPreviousPage') ? undefined : json['HasPreviousPage'],
        'isFirstPage': !(0, runtime_1.exists)(json, 'IsFirstPage') ? undefined : json['IsFirstPage'],
        'isLastPage': !(0, runtime_1.exists)(json, 'IsLastPage') ? undefined : json['IsLastPage'],
        'lastItemOnPage': !(0, runtime_1.exists)(json, 'LastItemOnPage') ? undefined : json['LastItemOnPage'],
        'list': !(0, runtime_1.exists)(json, 'List') ? undefined : (json['List'].map(ScanPolicySettingItemApiModel_1.ScanPolicySettingItemApiModelFromJSON)),
        'pageCount': !(0, runtime_1.exists)(json, 'PageCount') ? undefined : json['PageCount'],
        'pageNumber': !(0, runtime_1.exists)(json, 'PageNumber') ? undefined : json['PageNumber'],
        'pageSize': !(0, runtime_1.exists)(json, 'PageSize') ? undefined : json['PageSize'],
        'totalItemCount': !(0, runtime_1.exists)(json, 'TotalItemCount') ? undefined : json['TotalItemCount'],
    };
}
exports.ScanPolicyListApiResultFromJSONTyped = ScanPolicyListApiResultFromJSONTyped;
function ScanPolicyListApiResultToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'FirstItemOnPage': value.firstItemOnPage,
        'HasNextPage': value.hasNextPage,
        'HasPreviousPage': value.hasPreviousPage,
        'IsFirstPage': value.isFirstPage,
        'IsLastPage': value.isLastPage,
        'LastItemOnPage': value.lastItemOnPage,
        'List': value.list === undefined ? undefined : (value.list.map(ScanPolicySettingItemApiModel_1.ScanPolicySettingItemApiModelToJSON)),
        'PageCount': value.pageCount,
        'PageNumber': value.pageNumber,
        'PageSize': value.pageSize,
        'TotalItemCount': value.totalItemCount,
    };
}
exports.ScanPolicyListApiResultToJSON = ScanPolicyListApiResultToJSON;
//# sourceMappingURL=ScanPolicyListApiResult.js.map