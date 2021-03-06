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
* An utility class that helps to caching files with {Netsparker.Cloud.Infrastructure.Attributes.UploadedFileAttribute}.
*/
export class FileCache {
    'key'?: string;
    /**
    * Gets or sets the name of the file.
    */
    'fileName'?: string;
    /**
    * Gets or sets the identifier.
    */
    'id'?: number;
    /**
    * Gets or sets the accept.
    */
    'accept'?: string;
    /**
    * Gets or sets the type of the importer.
    */
    'importerType'?: FileCache.ImporterTypeEnum;
    /**
    * Gets or sets the url.
    */
    'uRL'?: string;
    /**
    * Gets or sets the api url.
    */
    'apiURL'?: string;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "key",
            "baseName": "Key",
            "type": "string"
        },
        {
            "name": "fileName",
            "baseName": "FileName",
            "type": "string"
        },
        {
            "name": "id",
            "baseName": "Id",
            "type": "number"
        },
        {
            "name": "accept",
            "baseName": "Accept",
            "type": "string"
        },
        {
            "name": "importerType",
            "baseName": "ImporterType",
            "type": "FileCache.ImporterTypeEnum"
        },
        {
            "name": "uRL",
            "baseName": "URL",
            "type": "string"
        },
        {
            "name": "apiURL",
            "baseName": "ApiURL",
            "type": "string"
        }    ];

    static getAttributeTypeMap() {
        return FileCache.attributeTypeMap;
    }
}

export namespace FileCache {
    export enum ImporterTypeEnum {
        None = <any> 'None',
        Fiddler = <any> 'Fiddler',
        Burp = <any> 'Burp',
        Swagger = <any> 'Swagger',
        OwaspZap = <any> 'OwaspZap',
        AspNet = <any> 'AspNet',
        HttpArchive = <any> 'HttpArchive',
        Wadl = <any> 'Wadl',
        Wsdl = <any> 'Wsdl',
        Postman = <any> 'Postman',
        Netsparker = <any> 'Netsparker',
        HttpRequestImporter = <any> 'HttpRequestImporter',
        LinkImporter = <any> 'LinkImporter',
        CsvImporter = <any> 'CsvImporter',
        Iodocs = <any> 'Iodocs',
        WordPress = <any> 'WordPress',
        Raml = <any> 'Raml',
        GraphQl = <any> 'GraphQl',
        AcxXml = <any> 'AcxXml'
    }
}
