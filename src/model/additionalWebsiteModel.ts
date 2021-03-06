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

/**
* Represents a website for additional scan targets.
*/
export class AdditionalWebsiteModel {
    /**
    * Gets or sets a value that specifies whether this website contains same content with the start URL.
    */
    'canonical'?: boolean;
    /**
    * Gets or sets the target URL.
    */
    'targetUrl'?: string;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "canonical",
            "baseName": "Canonical",
            "type": "boolean"
        },
        {
            "name": "targetUrl",
            "baseName": "TargetUrl",
            "type": "string"
        }    ];

    static getAttributeTypeMap() {
        return AdditionalWebsiteModel.attributeTypeMap;
    }
}

