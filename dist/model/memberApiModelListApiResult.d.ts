/**
 * Netsparker Enterprise API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: v1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */
import { MemberApiViewModel } from './memberApiViewModel';
export declare class MemberApiModelListApiResult {
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
    'list'?: Array<MemberApiViewModel>;
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
    static discriminator: string | undefined;
    static attributeTypeMap: Array<{
        name: string;
        baseName: string;
        type: string;
    }>;
    static getAttributeTypeMap(): {
        name: string;
        baseName: string;
        type: string;
    }[];
}
