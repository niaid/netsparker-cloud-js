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
exports.MemberApiModelListApiResultToJSON = exports.MemberApiModelListApiResultFromJSONTyped = exports.MemberApiModelListApiResultFromJSON = exports.instanceOfMemberApiModelListApiResult = void 0;
const MemberApiViewModel_1 = require("./MemberApiViewModel");
/**
 * Check if a given object implements the MemberApiModelListApiResult interface.
 */
function instanceOfMemberApiModelListApiResult(value) {
    return true;
}
exports.instanceOfMemberApiModelListApiResult = instanceOfMemberApiModelListApiResult;
function MemberApiModelListApiResultFromJSON(json) {
    return MemberApiModelListApiResultFromJSONTyped(json, false);
}
exports.MemberApiModelListApiResultFromJSON = MemberApiModelListApiResultFromJSON;
function MemberApiModelListApiResultFromJSONTyped(json, ignoreDiscriminator) {
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
        'list': json['List'] == null ? undefined : (json['List'].map(MemberApiViewModel_1.MemberApiViewModelFromJSON)),
        'pageCount': json['PageCount'] == null ? undefined : json['PageCount'],
        'pageNumber': json['PageNumber'] == null ? undefined : json['PageNumber'],
        'pageSize': json['PageSize'] == null ? undefined : json['PageSize'],
        'totalItemCount': json['TotalItemCount'] == null ? undefined : json['TotalItemCount'],
    };
}
exports.MemberApiModelListApiResultFromJSONTyped = MemberApiModelListApiResultFromJSONTyped;
function MemberApiModelListApiResultToJSON(value) {
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
        'List': value['list'] == null ? undefined : (value['list'].map(MemberApiViewModel_1.MemberApiViewModelToJSON)),
        'PageCount': value['pageCount'],
        'PageNumber': value['pageNumber'],
        'PageSize': value['pageSize'],
        'TotalItemCount': value['totalItemCount'],
    };
}
exports.MemberApiModelListApiResultToJSON = MemberApiModelListApiResultToJSON;
//# sourceMappingURL=MemberApiModelListApiResult.js.map