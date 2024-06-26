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
exports.NewScanTaskWithProfileApiModelToJSON = exports.NewScanTaskWithProfileApiModelFromJSONTyped = exports.NewScanTaskWithProfileApiModelFromJSON = exports.instanceOfNewScanTaskWithProfileApiModel = void 0;
/**
 * Check if a given object implements the NewScanTaskWithProfileApiModel interface.
 */
function instanceOfNewScanTaskWithProfileApiModel(value) {
    if (!('profileName' in value))
        return false;
    if (!('targetUri' in value))
        return false;
    return true;
}
exports.instanceOfNewScanTaskWithProfileApiModel = instanceOfNewScanTaskWithProfileApiModel;
function NewScanTaskWithProfileApiModelFromJSON(json) {
    return NewScanTaskWithProfileApiModelFromJSONTyped(json, false);
}
exports.NewScanTaskWithProfileApiModelFromJSON = NewScanTaskWithProfileApiModelFromJSON;
function NewScanTaskWithProfileApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'profileName': json['ProfileName'],
        'targetUri': json['TargetUri'],
    };
}
exports.NewScanTaskWithProfileApiModelFromJSONTyped = NewScanTaskWithProfileApiModelFromJSONTyped;
function NewScanTaskWithProfileApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'ProfileName': value['profileName'],
        'TargetUri': value['targetUri'],
    };
}
exports.NewScanTaskWithProfileApiModelToJSON = NewScanTaskWithProfileApiModelToJSON;
//# sourceMappingURL=NewScanTaskWithProfileApiModel.js.map