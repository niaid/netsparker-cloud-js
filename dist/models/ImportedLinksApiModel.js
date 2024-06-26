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
exports.ImportedLinksApiModelToJSON = exports.ImportedLinksApiModelFromJSONTyped = exports.ImportedLinksApiModelFromJSON = exports.instanceOfImportedLinksApiModel = void 0;
const ApiFile_1 = require("./ApiFile");
/**
 * Check if a given object implements the ImportedLinksApiModel interface.
 */
function instanceOfImportedLinksApiModel(value) {
    return true;
}
exports.instanceOfImportedLinksApiModel = instanceOfImportedLinksApiModel;
function ImportedLinksApiModelFromJSON(json) {
    return ImportedLinksApiModelFromJSONTyped(json, false);
}
exports.ImportedLinksApiModelFromJSON = ImportedLinksApiModelFromJSON;
function ImportedLinksApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'importedLinks': json['ImportedLinks'] == null ? undefined : json['ImportedLinks'],
        'files': json['Files'] == null ? undefined : (json['Files'].map(ApiFile_1.ApiFileFromJSON)),
    };
}
exports.ImportedLinksApiModelFromJSONTyped = ImportedLinksApiModelFromJSONTyped;
function ImportedLinksApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'ImportedLinks': value['importedLinks'],
        'Files': value['files'] == null ? undefined : (value['files'].map(ApiFile_1.ApiFileToJSON)),
    };
}
exports.ImportedLinksApiModelToJSON = ImportedLinksApiModelToJSON;
//# sourceMappingURL=ImportedLinksApiModel.js.map