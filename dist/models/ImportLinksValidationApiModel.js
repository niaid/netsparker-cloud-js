"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.ImportLinksValidationApiModelToJSON = exports.ImportLinksValidationApiModelFromJSONTyped = exports.ImportLinksValidationApiModelFromJSON = exports.instanceOfImportLinksValidationApiModel = exports.ImportLinksValidationApiModelImportTypeEnum = void 0;
const runtime_1 = require("../runtime");
/**
 * @export
 */
exports.ImportLinksValidationApiModelImportTypeEnum = {
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
};
/**
 * Check if a given object implements the ImportLinksValidationApiModel interface.
 */
function instanceOfImportLinksValidationApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "siteUrl" in value;
    return isInstance;
}
exports.instanceOfImportLinksValidationApiModel = instanceOfImportLinksValidationApiModel;
function ImportLinksValidationApiModelFromJSON(json) {
    return ImportLinksValidationApiModelFromJSONTyped(json, false);
}
exports.ImportLinksValidationApiModelFromJSON = ImportLinksValidationApiModelFromJSON;
function ImportLinksValidationApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'siteUrl': json['SiteUrl'],
        'importType': !(0, runtime_1.exists)(json, 'ImportType') ? undefined : json['ImportType'],
    };
}
exports.ImportLinksValidationApiModelFromJSONTyped = ImportLinksValidationApiModelFromJSONTyped;
function ImportLinksValidationApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'SiteUrl': value.siteUrl,
        'ImportType': value.importType,
    };
}
exports.ImportLinksValidationApiModelToJSON = ImportLinksValidationApiModelToJSON;
//# sourceMappingURL=ImportLinksValidationApiModel.js.map