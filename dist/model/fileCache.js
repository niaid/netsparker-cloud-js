"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.FileCache = void 0;
/**
* An utility class that helps to caching files with {Netsparker.Cloud.Infrastructure.Attributes.UploadedFileAttribute}.
*/
class FileCache {
    static getAttributeTypeMap() {
        return FileCache.attributeTypeMap;
    }
}
exports.FileCache = FileCache;
FileCache.discriminator = undefined;
FileCache.attributeTypeMap = [
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
    }
];
(function (FileCache) {
    let ImporterTypeEnum;
    (function (ImporterTypeEnum) {
        ImporterTypeEnum[ImporterTypeEnum["Fiddler"] = 'Fiddler'] = "Fiddler";
        ImporterTypeEnum[ImporterTypeEnum["Burp"] = 'Burp'] = "Burp";
        ImporterTypeEnum[ImporterTypeEnum["Swagger"] = 'Swagger'] = "Swagger";
        ImporterTypeEnum[ImporterTypeEnum["OwaspZap"] = 'OwaspZap'] = "OwaspZap";
        ImporterTypeEnum[ImporterTypeEnum["AspNet"] = 'AspNet'] = "AspNet";
        ImporterTypeEnum[ImporterTypeEnum["HttpArchive"] = 'HttpArchive'] = "HttpArchive";
        ImporterTypeEnum[ImporterTypeEnum["Wadl"] = 'Wadl'] = "Wadl";
        ImporterTypeEnum[ImporterTypeEnum["Wsdl"] = 'Wsdl'] = "Wsdl";
        ImporterTypeEnum[ImporterTypeEnum["Postman"] = 'Postman'] = "Postman";
        ImporterTypeEnum[ImporterTypeEnum["Netsparker"] = 'Netsparker'] = "Netsparker";
        ImporterTypeEnum[ImporterTypeEnum["HttpRequestImporter"] = 'HttpRequestImporter'] = "HttpRequestImporter";
        ImporterTypeEnum[ImporterTypeEnum["LinkImporter"] = 'LinkImporter'] = "LinkImporter";
        ImporterTypeEnum[ImporterTypeEnum["CsvImporter"] = 'CsvImporter'] = "CsvImporter";
        ImporterTypeEnum[ImporterTypeEnum["Iodocs"] = 'Iodocs'] = "Iodocs";
        ImporterTypeEnum[ImporterTypeEnum["WordPress"] = 'WordPress'] = "WordPress";
        ImporterTypeEnum[ImporterTypeEnum["Raml"] = 'Raml'] = "Raml";
    })(ImporterTypeEnum = FileCache.ImporterTypeEnum || (FileCache.ImporterTypeEnum = {}));
})(FileCache = exports.FileCache || (exports.FileCache = {}));
//# sourceMappingURL=fileCache.js.map