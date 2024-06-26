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
import type { WebsiteApiModel } from './WebsiteApiModel';
import {
    WebsiteApiModelFromJSON,
    WebsiteApiModelFromJSONTyped,
    WebsiteApiModelToJSON,
} from './WebsiteApiModel';

/**
 * Represents a model for carrying out a paged website list.
 * @export
 * @interface WebsiteListApiResult
 */
export interface WebsiteListApiResult {
    /**
     * 
     * @type {number}
     * @memberof WebsiteListApiResult
     */
    firstItemOnPage?: number;
    /**
     * 
     * @type {boolean}
     * @memberof WebsiteListApiResult
     */
    hasNextPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof WebsiteListApiResult
     */
    hasPreviousPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof WebsiteListApiResult
     */
    isFirstPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof WebsiteListApiResult
     */
    isLastPage?: boolean;
    /**
     * 
     * @type {number}
     * @memberof WebsiteListApiResult
     */
    lastItemOnPage?: number;
    /**
     * 
     * @type {Array<WebsiteApiModel>}
     * @memberof WebsiteListApiResult
     */
    list?: Array<WebsiteApiModel>;
    /**
     * 
     * @type {number}
     * @memberof WebsiteListApiResult
     */
    pageCount?: number;
    /**
     * 
     * @type {number}
     * @memberof WebsiteListApiResult
     */
    pageNumber?: number;
    /**
     * 
     * @type {number}
     * @memberof WebsiteListApiResult
     */
    pageSize?: number;
    /**
     * 
     * @type {number}
     * @memberof WebsiteListApiResult
     */
    totalItemCount?: number;
}

/**
 * Check if a given object implements the WebsiteListApiResult interface.
 */
export function instanceOfWebsiteListApiResult(value: object): boolean {
    return true;
}

export function WebsiteListApiResultFromJSON(json: any): WebsiteListApiResult {
    return WebsiteListApiResultFromJSONTyped(json, false);
}

export function WebsiteListApiResultFromJSONTyped(json: any, ignoreDiscriminator: boolean): WebsiteListApiResult {
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
        'list': json['List'] == null ? undefined : ((json['List'] as Array<any>).map(WebsiteApiModelFromJSON)),
        'pageCount': json['PageCount'] == null ? undefined : json['PageCount'],
        'pageNumber': json['PageNumber'] == null ? undefined : json['PageNumber'],
        'pageSize': json['PageSize'] == null ? undefined : json['PageSize'],
        'totalItemCount': json['TotalItemCount'] == null ? undefined : json['TotalItemCount'],
    };
}

export function WebsiteListApiResultToJSON(value?: WebsiteListApiResult | null): any {
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
        'List': value['list'] == null ? undefined : ((value['list'] as Array<any>).map(WebsiteApiModelToJSON)),
        'PageCount': value['pageCount'],
        'PageNumber': value['pageNumber'],
        'PageSize': value['pageSize'],
        'TotalItemCount': value['totalItemCount'],
    };
}

