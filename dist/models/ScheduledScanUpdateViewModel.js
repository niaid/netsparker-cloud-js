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
exports.ScheduledScanUpdateViewModelToJSON = exports.ScheduledScanUpdateViewModelFromJSONTyped = exports.ScheduledScanUpdateViewModelFromJSON = exports.instanceOfScheduledScanUpdateViewModel = void 0;
const runtime_1 = require("../runtime");
/**
 * Check if a given object implements the ScheduledScanUpdateViewModel interface.
 */
function instanceOfScheduledScanUpdateViewModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfScheduledScanUpdateViewModel = instanceOfScheduledScanUpdateViewModel;
function ScheduledScanUpdateViewModelFromJSON(json) {
    return ScheduledScanUpdateViewModelFromJSONTyped(json, false);
}
exports.ScheduledScanUpdateViewModelFromJSON = ScheduledScanUpdateViewModelFromJSON;
function ScheduledScanUpdateViewModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'id': !(0, runtime_1.exists)(json, 'Id') ? undefined : json['Id'],
        'name': !(0, runtime_1.exists)(json, 'Name') ? undefined : json['Name'],
    };
}
exports.ScheduledScanUpdateViewModelFromJSONTyped = ScheduledScanUpdateViewModelFromJSONTyped;
function ScheduledScanUpdateViewModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Id': value.id,
        'Name': value.name,
    };
}
exports.ScheduledScanUpdateViewModelToJSON = ScheduledScanUpdateViewModelToJSON;
//# sourceMappingURL=ScheduledScanUpdateViewModel.js.map