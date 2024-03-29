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
import type { ScanNotificationApiModel } from './ScanNotificationApiModel';
/**
 * Represents a model for carrying out a paged scan notification list.
 * @export
 * @interface ScanNotificationListApiResult
 */
export interface ScanNotificationListApiResult {
    /**
     *
     * @type {number}
     * @memberof ScanNotificationListApiResult
     */
    firstItemOnPage?: number;
    /**
     *
     * @type {boolean}
     * @memberof ScanNotificationListApiResult
     */
    hasNextPage?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof ScanNotificationListApiResult
     */
    hasPreviousPage?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof ScanNotificationListApiResult
     */
    isFirstPage?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof ScanNotificationListApiResult
     */
    isLastPage?: boolean;
    /**
     *
     * @type {number}
     * @memberof ScanNotificationListApiResult
     */
    lastItemOnPage?: number;
    /**
     *
     * @type {Array<ScanNotificationApiModel>}
     * @memberof ScanNotificationListApiResult
     */
    list?: Array<ScanNotificationApiModel>;
    /**
     *
     * @type {number}
     * @memberof ScanNotificationListApiResult
     */
    pageCount?: number;
    /**
     *
     * @type {number}
     * @memberof ScanNotificationListApiResult
     */
    pageNumber?: number;
    /**
     *
     * @type {number}
     * @memberof ScanNotificationListApiResult
     */
    pageSize?: number;
    /**
     *
     * @type {number}
     * @memberof ScanNotificationListApiResult
     */
    totalItemCount?: number;
}
/**
 * Check if a given object implements the ScanNotificationListApiResult interface.
 */
export declare function instanceOfScanNotificationListApiResult(value: object): boolean;
export declare function ScanNotificationListApiResultFromJSON(json: any): ScanNotificationListApiResult;
export declare function ScanNotificationListApiResultFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanNotificationListApiResult;
export declare function ScanNotificationListApiResultToJSON(value?: ScanNotificationListApiResult | null): any;
