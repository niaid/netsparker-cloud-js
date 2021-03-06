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
* Represents a model for carrying out ignored parameter patterns.
*/
export class IgnorePatternSettingModel {
    /**
    * Gets or sets the pattern name.
    */
    'name': string;
    /**
    * Gets or sets the type of the parameter.
    */
    'parameterType': IgnorePatternSettingModel.ParameterTypeEnum;
    /**
    * Gets or sets the RegEx pattern.
    */
    'pattern': string;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "name",
            "baseName": "Name",
            "type": "string"
        },
        {
            "name": "parameterType",
            "baseName": "ParameterType",
            "type": "IgnorePatternSettingModel.ParameterTypeEnum"
        },
        {
            "name": "pattern",
            "baseName": "Pattern",
            "type": "string"
        }    ];

    static getAttributeTypeMap() {
        return IgnorePatternSettingModel.attributeTypeMap;
    }
}

export namespace IgnorePatternSettingModel {
    export enum ParameterTypeEnum {
        Post = <any> 'POST',
        Get = <any> 'GET',
        Cookie = <any> 'COOKIE',
        Webstorage = <any> 'WEBSTORAGE',
        All = <any> 'ALL'
    }
}
