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
exports.IssueSummaryStatusModelToJSON = exports.IssueSummaryStatusModelFromJSONTyped = exports.IssueSummaryStatusModelFromJSON = exports.instanceOfIssueSummaryStatusModel = exports.IssueSummaryStatusModelStatusEnum = void 0;
/**
 * @export
 */
exports.IssueSummaryStatusModelStatusEnum = {
    Present: 'Present',
    FixedUnconfirmed: 'FixedUnconfirmed',
    FixedCantRetest: 'FixedCantRetest',
    FixedConfirmed: 'FixedConfirmed',
    Revived: 'Revived',
    Scanning: 'Scanning',
    Ignored: 'Ignored',
    AcceptedRisk: 'AcceptedRisk',
    FalsePositive: 'FalsePositive'
};
/**
 * Check if a given object implements the IssueSummaryStatusModel interface.
 */
function instanceOfIssueSummaryStatusModel(value) {
    return true;
}
exports.instanceOfIssueSummaryStatusModel = instanceOfIssueSummaryStatusModel;
function IssueSummaryStatusModelFromJSON(json) {
    return IssueSummaryStatusModelFromJSONTyped(json, false);
}
exports.IssueSummaryStatusModelFromJSON = IssueSummaryStatusModelFromJSON;
function IssueSummaryStatusModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'status': json['Status'] == null ? undefined : json['Status'],
        'statusDate': json['StatusDate'] == null ? undefined : json['StatusDate'],
    };
}
exports.IssueSummaryStatusModelFromJSONTyped = IssueSummaryStatusModelFromJSONTyped;
function IssueSummaryStatusModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Status': value['status'],
    };
}
exports.IssueSummaryStatusModelToJSON = IssueSummaryStatusModelToJSON;
//# sourceMappingURL=IssueSummaryStatusModel.js.map