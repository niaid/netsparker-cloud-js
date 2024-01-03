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
import type { AgentListApiModel } from './AgentListApiModel';
/**
 * Represents a model for carrying out a paged Agent list.
 * @export
 * @interface AgentListApiResult
 */
export interface AgentListApiResult {
    /**
     *
     * @type {number}
     * @memberof AgentListApiResult
     */
    firstItemOnPage?: number;
    /**
     *
     * @type {boolean}
     * @memberof AgentListApiResult
     */
    hasNextPage?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof AgentListApiResult
     */
    hasPreviousPage?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof AgentListApiResult
     */
    isFirstPage?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof AgentListApiResult
     */
    isLastPage?: boolean;
    /**
     *
     * @type {number}
     * @memberof AgentListApiResult
     */
    lastItemOnPage?: number;
    /**
     *
     * @type {Array<AgentListApiModel>}
     * @memberof AgentListApiResult
     */
    list?: Array<AgentListApiModel>;
    /**
     *
     * @type {number}
     * @memberof AgentListApiResult
     */
    pageCount?: number;
    /**
     *
     * @type {number}
     * @memberof AgentListApiResult
     */
    pageNumber?: number;
    /**
     *
     * @type {number}
     * @memberof AgentListApiResult
     */
    pageSize?: number;
    /**
     *
     * @type {number}
     * @memberof AgentListApiResult
     */
    totalItemCount?: number;
}
/**
 * Check if a given object implements the AgentListApiResult interface.
 */
export declare function instanceOfAgentListApiResult(value: object): boolean;
export declare function AgentListApiResultFromJSON(json: any): AgentListApiResult;
export declare function AgentListApiResultFromJSONTyped(json: any, ignoreDiscriminator: boolean): AgentListApiResult;
export declare function AgentListApiResultToJSON(value?: AgentListApiResult | null): any;