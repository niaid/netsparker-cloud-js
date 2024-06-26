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
import type { ScanTaskModel } from './ScanTaskModel';
import {
    ScanTaskModelFromJSON,
    ScanTaskModelFromJSONTyped,
    ScanTaskModelToJSON,
} from './ScanTaskModel';

/**
 * Represents a model for carrying out a paged scan task list.
 * @export
 * @interface ScanTaskListApiResult
 */
export interface ScanTaskListApiResult {
    /**
     * 
     * @type {number}
     * @memberof ScanTaskListApiResult
     */
    firstItemOnPage?: number;
    /**
     * 
     * @type {boolean}
     * @memberof ScanTaskListApiResult
     */
    hasNextPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof ScanTaskListApiResult
     */
    hasPreviousPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof ScanTaskListApiResult
     */
    isFirstPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof ScanTaskListApiResult
     */
    isLastPage?: boolean;
    /**
     * 
     * @type {number}
     * @memberof ScanTaskListApiResult
     */
    lastItemOnPage?: number;
    /**
     * 
     * @type {Array<ScanTaskModel>}
     * @memberof ScanTaskListApiResult
     */
    list?: Array<ScanTaskModel>;
    /**
     * 
     * @type {number}
     * @memberof ScanTaskListApiResult
     */
    pageCount?: number;
    /**
     * 
     * @type {number}
     * @memberof ScanTaskListApiResult
     */
    pageNumber?: number;
    /**
     * 
     * @type {number}
     * @memberof ScanTaskListApiResult
     */
    pageSize?: number;
    /**
     * 
     * @type {number}
     * @memberof ScanTaskListApiResult
     */
    totalItemCount?: number;
}

/**
 * Check if a given object implements the ScanTaskListApiResult interface.
 */
export function instanceOfScanTaskListApiResult(value: object): boolean {
    return true;
}

export function ScanTaskListApiResultFromJSON(json: any): ScanTaskListApiResult {
    return ScanTaskListApiResultFromJSONTyped(json, false);
}

export function ScanTaskListApiResultFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanTaskListApiResult {
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
        'list': json['List'] == null ? undefined : ((json['List'] as Array<any>).map(ScanTaskModelFromJSON)),
        'pageCount': json['PageCount'] == null ? undefined : json['PageCount'],
        'pageNumber': json['PageNumber'] == null ? undefined : json['PageNumber'],
        'pageSize': json['PageSize'] == null ? undefined : json['PageSize'],
        'totalItemCount': json['TotalItemCount'] == null ? undefined : json['TotalItemCount'],
    };
}

export function ScanTaskListApiResultToJSON(value?: ScanTaskListApiResult | null): any {
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
        'List': value['list'] == null ? undefined : ((value['list'] as Array<any>).map(ScanTaskModelToJSON)),
        'PageCount': value['pageCount'],
        'PageNumber': value['pageNumber'],
        'PageSize': value['pageSize'],
        'TotalItemCount': value['totalItemCount'],
    };
}

