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
import { ContentTypeTemplate } from './contentTypeTemplate';
import { SelectOptionModel } from './selectOptionModel';
/**
* Represents a oauth2 endpoint model.
*/
export declare class OAuth2SettingEndPointModel {
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