/* tslint:disable */
/* eslint-disable */
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

import { mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface ImportLinksValidationApiModel
 */
export interface ImportLinksValidationApiModel {
    /**
     * Gets or sets the site url for import links.
     * @type {string}
     * @memberof ImportLinksValidationApiModel
     */
    siteUrl: string;
    /**
     * Gets or sets the the file import type.
     * @type {string}
     * @memberof ImportLinksValidationApiModel
     */
    importType?: ImportLinksValidationApiModelImportTypeEnum;
}


/**
 * @export
 */
export const ImportLinksValidationApiModelImportTypeEnum = {
    None: 'None',
    Fiddler: 'Fiddler',
    Burp: 'Burp',
    Swagger: 'Swagger',
    OwaspZap: 'OwaspZap',
    AspNet: 'AspNet',
    HttpArchive: 'HttpArchive',
    Wadl: 'Wadl',
    Wsdl: 'Wsdl',
    Postman: 'Postman',
    InvictiSessionFile: 'InvictiSessionFile',
    CsvImporter: 'CsvImporter',
    Iodocs: 'Iodocs',
    WordPress: 'WordPress',
    Raml: 'Raml',
    GraphQl: 'GraphQl'
} as const;
export type ImportLinksValidationApiModelImportTypeEnum = typeof ImportLinksValidationApiModelImportTypeEnum[keyof typeof ImportLinksValidationApiModelImportTypeEnum];


/**
 * Check if a given object implements the ImportLinksValidationApiModel interface.
 */
export function instanceOfImportLinksValidationApiModel(value: object): boolean {
    if (!('siteUrl' in value)) return false;
    return true;
}

export function ImportLinksValidationApiModelFromJSON(json: any): ImportLinksValidationApiModel {
    return ImportLinksValidationApiModelFromJSONTyped(json, false);
}

export function ImportLinksValidationApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ImportLinksValidationApiModel {
    if (json == null) {
        return json;
    }
    return {
        
        'siteUrl': json['SiteUrl'],
        'importType': json['ImportType'] == null ? undefined : json['ImportType'],
    };
}

export function ImportLinksValidationApiModelToJSON(value?: ImportLinksValidationApiModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'SiteUrl': value['siteUrl'],
        'ImportType': value['importType'],
    };
}

