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
/**
 * Check if a given object implements the ScheduledScanUpdateViewModel interface.
 */
function instanceOfScheduledScanUpdateViewModel(value) {
    return true;
}
exports.instanceOfScheduledScanUpdateViewModel = instanceOfScheduledScanUpdateViewModel;
function ScheduledScanUpdateViewModelFromJSON(json) {
    return ScheduledScanUpdateViewModelFromJSONTyped(json, false);
}
exports.ScheduledScanUpdateViewModelFromJSON = ScheduledScanUpdateViewModelFromJSON;
function ScheduledScanUpdateViewModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'id': json['Id'] == null ? undefined : json['Id'],
        'name': json['Name'] == null ? undefined : json['Name'],
    };
}
exports.ScheduledScanUpdateViewModelFromJSONTyped = ScheduledScanUpdateViewModelFromJSONTyped;
function ScheduledScanUpdateViewModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Id': value['id'],
        'Name': value['name'],
    };
}
exports.ScheduledScanUpdateViewModelToJSON = ScheduledScanUpdateViewModelToJSON;
//# sourceMappingURL=ScheduledScanUpdateViewModel.js.map