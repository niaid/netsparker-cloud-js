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

import { exists, mapValues } from '../runtime';
import type { IssueApiModel } from './IssueApiModel';
import {
    IssueApiModelFromJSON,
    IssueApiModelFromJSONTyped,
    IssueApiModelToJSON,
} from './IssueApiModel';

/**
 * Paged list api model.
 * @export
 * @interface IssueApiResult
 */
export interface IssueApiResult {
    /**
     * 
     * @type {number}
     * @memberof IssueApiResult
     */
    firstItemOnPage?: number;
    /**
     * 
     * @type {boolean}
     * @memberof IssueApiResult
     */
    hasNextPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof IssueApiResult
     */
    hasPreviousPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof IssueApiResult
     */
    isFirstPage?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof IssueApiResult
     */
    isLastPage?: boolean;
    /**
     * 
     * @type {number}
     * @memberof IssueApiResult
     */
    lastItemOnPage?: number;
    /**
     * 
     * @type {Array<IssueApiModel>}
     * @memberof IssueApiResult
     */
    list?: Array<IssueApiModel>;
    /**
     * 
     * @type {number}
     * @memberof IssueApiResult
     */
    pageCount?: number;
    /**
     * 
     * @type {number}
     * @memberof IssueApiResult
     */
    pageNumber?: number;
    /**
     * 
     * @type {number}
     * @memberof IssueApiResult
     */
    pageSize?: number;
    /**
     * 
     * @type {number}
     * @memberof IssueApiResult
     */
    totalItemCount?: number;
}

/**
 * Check if a given object implements the IssueApiResult interface.
 */
export function instanceOfIssueApiResult(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function IssueApiResultFromJSON(json: any): IssueApiResult {
    return IssueApiResultFromJSONTyped(json, false);
}

export function IssueApiResultFromJSONTyped(json: any, ignoreDiscriminator: boolean): IssueApiResult {
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
        'list': !exists(json, 'List') ? undefined : ((json['List'] as Array<any>).map(IssueApiModelFromJSON)),
        'pageCount': !exists(json, 'PageCount') ? undefined : json['PageCount'],
        'pageNumber': !exists(json, 'PageNumber') ? undefined : json['PageNumber'],
        'pageSize': !exists(json, 'PageSize') ? undefined : json['PageSize'],
        'totalItemCount': !exists(json, 'TotalItemCount') ? undefined : json['TotalItemCount'],
    };
}

export function IssueApiResultToJSON(value?: IssueApiResult | null): any {
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
        'List': value.list === undefined ? undefined : ((value.list as Array<any>).map(IssueApiModelToJSON)),
        'PageCount': value.pageCount,
        'PageNumber': value.pageNumber,
        'PageSize': value.pageSize,
        'TotalItemCount': value.totalItemCount,
    };
}
