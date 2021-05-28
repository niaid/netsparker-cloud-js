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
* Represents an URL Rewrite Exclude Path rule
*/
export class UrlRewriteExcludedPathModel {
    /**
    * Gets or sets the excluded path.
    */
    'excludedPath'?: string;
    /**
    * Gets or sets a value indicating whether this instance is regex.
    */
    'isRegex'?: boolean;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "excludedPath",
            "baseName": "ExcludedPath",
            "type": "string"
        },
        {
            "name": "isRegex",
            "baseName": "IsRegex",
            "type": "boolean"
        }    ];

    static getAttributeTypeMap() {
        return UrlRewriteExcludedPathModel.attributeTypeMap;
    }
}
