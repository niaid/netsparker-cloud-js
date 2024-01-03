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
import { exists } from '../runtime';
import { MemberApiViewModelFromJSON, MemberApiViewModelToJSON, } from './MemberApiViewModel';
/**
 * Check if a given object implements the MemberApiModelListApiResult interface.
 */
export function instanceOfMemberApiModelListApiResult(value) {
    let isInstance = true;
    return isInstance;
}
export function MemberApiModelListApiResultFromJSON(json) {
    return MemberApiModelListApiResultFromJSONTyped(json, false);
}
export function MemberApiModelListApiResultFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'firstItemOnPage': !exists(json, 'FirstItemOnPage') ? undefined : json['FirstItemOnPage'],
        'hasNextPage': !exists(json, 'HasNextPage') ? undefined : json['HasNextPage'],
        'hasPreviousPage': !exists(json, 'HasPreviousPage') ? undefined : json['HasPreviousPage'],
        'isFirstPage': !exists(json, 'IsFirstPage') ? undefined : json['IsFirstPage'],
        'isLastPage': !exists(json, 'IsLastPage') ? undefined : json['IsLastPage'],
        'lastItemOnPage': !exists(json, 'LastItemOnPage') ? undefined : json['LastItemOnPage'],
        'list': !exists(json, 'List') ? undefined : (json['List'].map(MemberApiViewModelFromJSON)),
        'pageCount': !exists(json, 'PageCount') ? undefined : json['PageCount'],
        'pageNumber': !exists(json, 'PageNumber') ? undefined : json['PageNumber'],
        'pageSize': !exists(json, 'PageSize') ? undefined : json['PageSize'],
        'totalItemCount': !exists(json, 'TotalItemCount') ? undefined : json['TotalItemCount'],
    };
}
export function MemberApiModelListApiResultToJSON(value) {
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
        'List': value.list === undefined ? undefined : (value.list.map(MemberApiViewModelToJSON)),
        'PageCount': value.pageCount,
        'PageNumber': value.pageNumber,
        'PageSize': value.pageSize,
        'TotalItemCount': value.totalItemCount,
    };
}
//# sourceMappingURL=MemberApiModelListApiResult.js.map