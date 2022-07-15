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
import { ContentTypeTemplate } from './contentTypeTemplate';
import { SelectOptionModel } from './selectOptionModel';

/**
* Represents a oauth2 endpoint model.
*/
export class OAuth2SettingEndPointModel {
    /**
    * Gets or sets the url
    */
    'url'?: string;
    /**
    * Gets or sets the content type
    */
    'contentType'?: string;
    /**
    * Gets or sets the content type templates
    */
    'contentTypeTemplates'?: Array<ContentTypeTemplate>;
    /**
    * Gets or sets the method
    */
    'method'?: string;
    /**
    * Gets or sets the method templates
    */
    'methodTemplates'?: Array<SelectOptionModel>;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "url",
            "baseName": "Url",
            "type": "string"
        },
        {
            "name": "contentType",
            "baseName": "ContentType",
            "type": "string"
        },
        {
            "name": "contentTypeTemplates",
            "baseName": "ContentTypeTemplates",
            "type": "Array<ContentTypeTemplate>"
        },
        {
            "name": "method",
            "baseName": "Method",
            "type": "string"
        },
        {
            "name": "methodTemplates",
            "baseName": "MethodTemplates",
            "type": "Array<SelectOptionModel>"
        }    ];

    static getAttributeTypeMap() {
        return OAuth2SettingEndPointModel.attributeTypeMap;
    }
}

