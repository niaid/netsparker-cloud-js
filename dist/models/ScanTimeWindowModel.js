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
exports.ScanTimeWindowModelToJSON = exports.ScanTimeWindowModelFromJSONTyped = exports.ScanTimeWindowModelFromJSON = exports.instanceOfScanTimeWindowModel = void 0;
const ScanTimeWindowItemModel_1 = require("./ScanTimeWindowItemModel");
/**
 * Check if a given object implements the ScanTimeWindowModel interface.
 */
function instanceOfScanTimeWindowModel(value) {
    return true;
}
exports.instanceOfScanTimeWindowModel = instanceOfScanTimeWindowModel;
function ScanTimeWindowModelFromJSON(json) {
    return ScanTimeWindowModelFromJSONTyped(json, false);
}
exports.ScanTimeWindowModelFromJSON = ScanTimeWindowModelFromJSON;
function ScanTimeWindowModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'items': json['Items'] == null ? undefined : (json['Items'].map(ScanTimeWindowItemModel_1.ScanTimeWindowItemModelFromJSON)),
    };
}
exports.ScanTimeWindowModelFromJSONTyped = ScanTimeWindowModelFromJSONTyped;
function ScanTimeWindowModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Items': value['items'] == null ? undefined : (value['items'].map(ScanTimeWindowItemModel_1.ScanTimeWindowItemModelToJSON)),
    };
}
exports.ScanTimeWindowModelToJSON = ScanTimeWindowModelToJSON;
//# sourceMappingURL=ScanTimeWindowModel.js.map