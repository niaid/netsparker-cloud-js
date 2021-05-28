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

import { RequestFile } from './models';

/**
* Represents a model for carrying out website groups data.
*/
export class WebsiteGroupModel {
    /**
    * Gets the display name.
    */
    'displayName'?: string;
    /**
    * Gets or sets the group identifier.
    */
    'id'?: string;
    /**
    * Gets or sets the group name.
    */
    'name'?: string;
    /**
    * Gets or sets the not verified website count.
    */
    'notVerifiedWebsiteCount'?: number;
    /**
    * Gets or sets the verified website count.
    */
    'verifiedWebsiteCount'?: number;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "displayName",
            "baseName": "DisplayName",
            "type": "string"
        },
        {
            "name": "id",
            "baseName": "Id",
            "type": "string"
        },
        {
            "name": "name",
            "baseName": "Name",
            "type": "string"
        },
        {
            "name": "notVerifiedWebsiteCount",
            "baseName": "NotVerifiedWebsiteCount",
            "type": "number"
        },
        {
            "name": "verifiedWebsiteCount",
            "baseName": "VerifiedWebsiteCount",
            "type": "number"
        }    ];

    static getAttributeTypeMap() {
        return WebsiteGroupModel.attributeTypeMap;
    }
}
