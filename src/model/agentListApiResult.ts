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

import { RequestFile } from './models';
import { AgentListApiModel } from './agentListApiModel';

/**
* Represents a model for carrying out a paged Agent list.
*/
export class AgentListApiResult {
    /**
    * Gets or sets the first item on page.
    */
    'firstItemOnPage'?: number;
    /**
    * Gets or sets a value indicating whether this instance has next page.
    */
    'hasNextPage'?: boolean;
    /**
    * Gets or sets a value indicating whether this instance has previous page.
    */
    'hasPreviousPage'?: boolean;
    /**
    * Gets or sets a value indicating whether this instance is first page.
    */
    'isFirstPage'?: boolean;
    /**
    * Gets or sets a value indicating whether this instance is last page.
    */
    'isLastPage'?: boolean;
    /**
    * Gets or sets the last item on page.
    */
    'lastItemOnPage'?: number;
    /**
    * Gets or sets the list.
    */
    'list'?: Array<AgentListApiModel>;
    /**
    * Gets or sets the page count.
    */
    'pageCount'?: number;
    /**
    * Gets or sets the page number.
    */
    'pageNumber'?: number;
    /**
    * Gets or sets the size of the page.
    */
    'pageSize'?: number;
    /**
    * Gets or sets the total item count.
    */
    'totalItemCount'?: number;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "firstItemOnPage",
            "baseName": "FirstItemOnPage",
            "type": "number"
        },
        {
            "name": "hasNextPage",
            "baseName": "HasNextPage",
            "type": "boolean"
        },
        {
            "name": "hasPreviousPage",
            "baseName": "HasPreviousPage",
            "type": "boolean"
        },
        {
            "name": "isFirstPage",
            "baseName": "IsFirstPage",
            "type": "boolean"
        },
        {
            "name": "isLastPage",
            "baseName": "IsLastPage",
            "type": "boolean"
        },
        {
            "name": "lastItemOnPage",
            "baseName": "LastItemOnPage",
            "type": "number"
        },
        {
            "name": "list",
            "baseName": "List",
            "type": "Array<AgentListApiModel>"
        },
        {
            "name": "pageCount",
            "baseName": "PageCount",
            "type": "number"
        },
        {
            "name": "pageNumber",
            "baseName": "PageNumber",
            "type": "number"
        },
        {
            "name": "pageSize",
            "baseName": "PageSize",
            "type": "number"
        },
        {
            "name": "totalItemCount",
            "baseName": "TotalItemCount",
            "type": "number"
        }    ];

    static getAttributeTypeMap() {
        return AgentListApiResult.attributeTypeMap;
    }
}

