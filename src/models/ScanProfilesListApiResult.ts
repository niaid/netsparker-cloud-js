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
import type { SaveScanProfileApiModel } from './SaveScanProfileApiModel';
import {
    SaveScanProfileApiModelFromJSON,
    SaveScanProfileApiModelFromJSONTyped,
    SaveScanProfileApiModelToJSON,
} from './SaveScanProfileApiModel';

/**
 * Represents a model for carrying out a paged scan profile list.
 * @export
 * @interface ScanProfilesListApiResult
 */
export interface ScanProfilesListApiResult {
    /**
     * 
     * @type {number}
     * @memberof ScanProfilesListApiResult
     */
    firstItemOnPage?: number;
    /**
     * 
     * @type {boolean}
     * @memberof ScanProfilesListApiResult
     */
    hasNextPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof ScanProfilesListApiResult
     */
    hasPreviousPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof ScanProfilesListApiResult
     */
    isFirstPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof ScanProfilesListApiResult
     */
    isLastPage?: boolean;
    /**
     * 
     * @type {number}
     * @memberof ScanProfilesListApiResult
     */
    lastItemOnPage?: number;
    /**
     * 
     * @type {Array<SaveScanProfileApiModel>}
     * @memberof ScanProfilesListApiResult
     */
    list?: Array<SaveScanProfileApiModel>;
    /**
     * 
     * @type {number}
     * @memberof ScanProfilesListApiResult
     */
    pageCount?: number;
    /**
     * 
     * @type {number}
     * @memberof ScanProfilesListApiResult
     */
    pageNumber?: number;
    /**
     * 
     * @type {number}
     * @memberof ScanProfilesListApiResult
     */
    pageSize?: number;
    /**
     * 
     * @type {number}
     * @memberof ScanProfilesListApiResult
     */
    totalItemCount?: number;
}

/**
 * Check if a given object implements the ScanProfilesListApiResult interface.
 */
export function instanceOfScanProfilesListApiResult(value: object): boolean {
    return true;
}

export function ScanProfilesListApiResultFromJSON(json: any): ScanProfilesListApiResult {
    return ScanProfilesListApiResultFromJSONTyped(json, false);
}

export function ScanProfilesListApiResultFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanProfilesListApiResult {
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
        'list': json['List'] == null ? undefined : ((json['List'] as Array<any>).map(SaveScanProfileApiModelFromJSON)),
        'pageCount': json['PageCount'] == null ? undefined : json['PageCount'],
        'pageNumber': json['PageNumber'] == null ? undefined : json['PageNumber'],
        'pageSize': json['PageSize'] == null ? undefined : json['PageSize'],
        'totalItemCount': json['TotalItemCount'] == null ? undefined : json['TotalItemCount'],
    };
}

export function ScanProfilesListApiResultToJSON(value?: ScanProfilesListApiResult | null): any {
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
        'List': value['list'] == null ? undefined : ((value['list'] as Array<any>).map(SaveScanProfileApiModelToJSON)),
        'PageCount': value['pageCount'],
        'PageNumber': value['pageNumber'],
        'PageSize': value['pageSize'],
        'TotalItemCount': value['totalItemCount'],
    };
}

