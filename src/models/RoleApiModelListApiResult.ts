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

import { mapValues } from '../runtime';
import type { RoleApiViewModel } from './RoleApiViewModel';
import {
    RoleApiViewModelFromJSON,
    RoleApiViewModelFromJSONTyped,
    RoleApiViewModelToJSON,
} from './RoleApiViewModel';

/**
 * 
 * @export
 * @interface RoleApiModelListApiResult
 */
export interface RoleApiModelListApiResult {
    /**
     * 
     * @type {number}
     * @memberof RoleApiModelListApiResult
     */
    firstItemOnPage?: number;
    /**
     * 
     * @type {boolean}
     * @memberof RoleApiModelListApiResult
     */
    hasNextPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof RoleApiModelListApiResult
     */
    hasPreviousPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof RoleApiModelListApiResult
     */
    isFirstPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof RoleApiModelListApiResult
     */
    isLastPage?: boolean;
    /**
     * 
     * @type {number}
     * @memberof RoleApiModelListApiResult
     */
    lastItemOnPage?: number;
    /**
     * 
     * @type {Array<RoleApiViewModel>}
     * @memberof RoleApiModelListApiResult
     */
    list?: Array<RoleApiViewModel>;
    /**
     * 
     * @type {number}
     * @memberof RoleApiModelListApiResult
     */
    pageCount?: number;
    /**
     * 
     * @type {number}
     * @memberof RoleApiModelListApiResult
     */
    pageNumber?: number;
    /**
     * 
     * @type {number}
     * @memberof RoleApiModelListApiResult
     */
    pageSize?: number;
    /**
     * 
     * @type {number}
     * @memberof RoleApiModelListApiResult
     */
    totalItemCount?: number;
}

/**
 * Check if a given object implements the RoleApiModelListApiResult interface.
 */
export function instanceOfRoleApiModelListApiResult(value: object): boolean {
    return true;
}

export function RoleApiModelListApiResultFromJSON(json: any): RoleApiModelListApiResult {
    return RoleApiModelListApiResultFromJSONTyped(json, false);
}

export function RoleApiModelListApiResultFromJSONTyped(json: any, ignoreDiscriminator: boolean): RoleApiModelListApiResult {
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
        'list': json['List'] == null ? undefined : ((json['List'] as Array<any>).map(RoleApiViewModelFromJSON)),
        'pageCount': json['PageCount'] == null ? undefined : json['PageCount'],
        'pageNumber': json['PageNumber'] == null ? undefined : json['PageNumber'],
        'pageSize': json['PageSize'] == null ? undefined : json['PageSize'],
        'totalItemCount': json['TotalItemCount'] == null ? undefined : json['TotalItemCount'],
    };
}

export function RoleApiModelListApiResultToJSON(value?: RoleApiModelListApiResult | null): any {
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
        'List': value['list'] == null ? undefined : ((value['list'] as Array<any>).map(RoleApiViewModelToJSON)),
        'PageCount': value['pageCount'],
        'PageNumber': value['pageNumber'],
        'PageSize': value['pageSize'],
        'TotalItemCount': value['totalItemCount'],
    };
}

