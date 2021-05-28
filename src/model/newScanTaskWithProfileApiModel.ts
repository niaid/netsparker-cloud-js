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
* Contains properties that required to start a scan according to profile specified.
*/
export class NewScanTaskWithProfileApiModel {
    /**
    * Gets or sets the profile id.
    */
    'profileName': string;
    /**
    * Gets or sets the target URI.
    */
    'targetUri': string;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "profileName",
            "baseName": "ProfileName",
            "type": "string"
        },
        {
            "name": "targetUri",
            "baseName": "TargetUri",
            "type": "string"
        }    ];

    static getAttributeTypeMap() {
        return NewScanTaskWithProfileApiModel.attributeTypeMap;
    }
}
