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
exports.ScanControlApiModelToJSON = exports.ScanControlApiModelFromJSONTyped = exports.ScanControlApiModelFromJSON = exports.instanceOfScanControlApiModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the ScanControlApiModel interface.
 */
function instanceOfScanControlApiModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfScanControlApiModel = instanceOfScanControlApiModel;
function ScanControlApiModelFromJSON(json) {
    return ScanControlApiModelFromJSONTyped(json, false);
}
exports.ScanControlApiModelFromJSON = ScanControlApiModelFromJSON;
function ScanControlApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'isScansSuspended': !(0, runtime_1.exists)(json, 'IsScansSuspended') ? undefined : json['IsScansSuspended'],
    };
}
exports.ScanControlApiModelFromJSONTyped = ScanControlApiModelFromJSONTyped;
function ScanControlApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'IsScansSuspended': value.isScansSuspended,
    };
}
exports.ScanControlApiModelToJSON = ScanControlApiModelToJSON;
//# sourceMappingURL=ScanControlApiModel.js.map