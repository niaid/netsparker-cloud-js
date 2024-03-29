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
const runtime_1 = require("../runtime");
const ScanTimeWindowItemModel_1 = require("./ScanTimeWindowItemModel");
/**
 * Check if a given object implements the ScanTimeWindowModel interface.
 */
function instanceOfScanTimeWindowModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfScanTimeWindowModel = instanceOfScanTimeWindowModel;
function ScanTimeWindowModelFromJSON(json) {
    return ScanTimeWindowModelFromJSONTyped(json, false);
}
exports.ScanTimeWindowModelFromJSON = ScanTimeWindowModelFromJSON;
function ScanTimeWindowModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'items': !(0, runtime_1.exists)(json, 'Items') ? undefined : (json['Items'].map(ScanTimeWindowItemModel_1.ScanTimeWindowItemModelFromJSON)),
    };
}
exports.ScanTimeWindowModelFromJSONTyped = ScanTimeWindowModelFromJSONTyped;
function ScanTimeWindowModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Items': value.items === undefined ? undefined : (value.items.map(ScanTimeWindowItemModel_1.ScanTimeWindowItemModelToJSON)),
    };
}
exports.ScanTimeWindowModelToJSON = ScanTimeWindowModelToJSON;
//# sourceMappingURL=ScanTimeWindowModel.js.map