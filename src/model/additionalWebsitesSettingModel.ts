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
import { AdditionalWebsiteModel } from './additionalWebsiteModel';

/**
* Represents a model for carrying out additional websites.
*/
export class AdditionalWebsitesSettingModel {
    /**
    * Gets or sets the additional websites to scan.
    */
    'websites'?: Array<AdditionalWebsiteModel>;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "websites",
            "baseName": "Websites",
            "type": "Array<AdditionalWebsiteModel>"
        }    ];

    static getAttributeTypeMap() {
        return AdditionalWebsitesSettingModel.attributeTypeMap;
    }
}

