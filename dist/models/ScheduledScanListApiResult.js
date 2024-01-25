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
exports.ScheduledScanListApiResultToJSON = exports.ScheduledScanListApiResultFromJSONTyped = exports.ScheduledScanListApiResultFromJSON = exports.instanceOfScheduledScanListApiResult = void 0;
const runtime_1 = require("../runtime");
const ScheduledScanModel_1 = require("./ScheduledScanModel");
/**
 * Check if a given object implements the ScheduledScanListApiResult interface.
 */
function instanceOfScheduledScanListApiResult(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfScheduledScanListApiResult = instanceOfScheduledScanListApiResult;
function ScheduledScanListApiResultFromJSON(json) {
    return ScheduledScanListApiResultFromJSONTyped(json, false);
}
exports.ScheduledScanListApiResultFromJSON = ScheduledScanListApiResultFromJSON;
function ScheduledScanListApiResultFromJSONTyped(json, ignoreDiscriminator) {
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
        'list': !(0, runtime_1.exists)(json, 'List') ? undefined : (json['List'].map(ScheduledScanModel_1.ScheduledScanModelFromJSON)),
        'pageCount': !(0, runtime_1.exists)(json, 'PageCount') ? undefined : json['PageCount'],
        'pageNumber': !(0, runtime_1.exists)(json, 'PageNumber') ? undefined : json['PageNumber'],
        'pageSize': !(0, runtime_1.exists)(json, 'PageSize') ? undefined : json['PageSize'],
        'totalItemCount': !(0, runtime_1.exists)(json, 'TotalItemCount') ? undefined : json['TotalItemCount'],
    };
}
exports.ScheduledScanListApiResultFromJSONTyped = ScheduledScanListApiResultFromJSONTyped;
function ScheduledScanListApiResultToJSON(value) {
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
        'List': value.list === undefined ? undefined : (value.list.map(ScheduledScanModel_1.ScheduledScanModelToJSON)),
        'PageCount': value.pageCount,
        'PageNumber': value.pageNumber,
        'PageSize': value.pageSize,
        'TotalItemCount': value.totalItemCount,
    };
}
exports.ScheduledScanListApiResultToJSON = ScheduledScanListApiResultToJSON;
//# sourceMappingURL=ScheduledScanListApiResult.js.map