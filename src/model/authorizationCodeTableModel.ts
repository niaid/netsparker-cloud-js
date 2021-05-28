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
import { NameValuePair } from './nameValuePair';

/**
* Represents authorization code table model for oauth2.
*/
export class AuthorizationCodeTableModel {
    /**
    * Gets or sets the table column names.
    */
    'fields'?: Array<string>;
    /**
    * Gets or sets the authorization code table items.
    */
    'items'?: Array<NameValuePair>;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "fields",
            "baseName": "Fields",
            "type": "Array<string>"
        },
        {
            "name": "items",
            "baseName": "Items",
            "type": "Array<NameValuePair>"
        }    ];

    static getAttributeTypeMap() {
        return AuthorizationCodeTableModel.attributeTypeMap;
    }
}
