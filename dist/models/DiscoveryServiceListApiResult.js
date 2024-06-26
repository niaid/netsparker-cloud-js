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
exports.DiscoveryServiceListApiResultToJSON = exports.DiscoveryServiceListApiResultFromJSONTyped = exports.DiscoveryServiceListApiResultFromJSON = exports.instanceOfDiscoveryServiceListApiResult = void 0;
const DiscoveryApiModel_1 = require("./DiscoveryApiModel");
/**
 * Check if a given object implements the DiscoveryServiceListApiResult interface.
 */
function instanceOfDiscoveryServiceListApiResult(value) {
    return true;
}
exports.instanceOfDiscoveryServiceListApiResult = instanceOfDiscoveryServiceListApiResult;
function DiscoveryServiceListApiResultFromJSON(json) {
    return DiscoveryServiceListApiResultFromJSONTyped(json, false);
}
exports.DiscoveryServiceListApiResultFromJSON = DiscoveryServiceListApiResultFromJSON;
function DiscoveryServiceListApiResultFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'firstItemOnPage': json['FirstItemOnPage'] == null ? undefined : json['FirstItemOnPage'],
        'hasNextPage': json['HasNextPage'] == null ? undefined : json['HasNextPage'],
        'hasPreviousPage': json['HasPreviousPage'] == null ? undefined : json['HasPreviousPage'],
        'isFirstPage': json['IsFirstPage'] == null ? undefined : json['IsFirstPage'],
        'isLastPage': json['IsLastPage'] == null ? undefined : json['IsLastPage'],
        'lastItemOnPage': json['LastItemOnPage'] == null ? undefined : json['LastItemOnPage'],
        'list': json['List'] == null ? undefined : (json['List'].map(DiscoveryApiModel_1.DiscoveryApiModelFromJSON)),
        'pageCount': json['PageCount'] == null ? undefined : json['PageCount'],
        'pageNumber': json['PageNumber'] == null ? undefined : json['PageNumber'],
        'pageSize': json['PageSize'] == null ? undefined : json['PageSize'],
        'totalItemCount': json['TotalItemCount'] == null ? undefined : json['TotalItemCount'],
    };
}
exports.DiscoveryServiceListApiResultFromJSONTyped = DiscoveryServiceListApiResultFromJSONTyped;
function DiscoveryServiceListApiResultToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'FirstItemOnPage': value['firstItemOnPage'],
        'HasNextPage': value['hasNextPage'],
        'HasPreviousPage': value['hasPreviousPage'],
        'IsFirstPage': value['isFirstPage'],
        'IsLastPage': value['isLastPage'],
        'LastItemOnPage': value['lastItemOnPage'],
        'List': value['list'] == null ? undefined : (value['list'].map(DiscoveryApiModel_1.DiscoveryApiModelToJSON)),
        'PageCount': value['pageCount'],
        'PageNumber': value['pageNumber'],
        'PageSize': value['pageSize'],
        'TotalItemCount': value['totalItemCount'],
    };
}
exports.DiscoveryServiceListApiResultToJSON = DiscoveryServiceListApiResultToJSON;
//# sourceMappingURL=DiscoveryServiceListApiResult.js.map