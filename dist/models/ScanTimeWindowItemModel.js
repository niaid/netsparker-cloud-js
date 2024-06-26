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
exports.ScanTimeWindowItemModelToJSON = exports.ScanTimeWindowItemModelFromJSONTyped = exports.ScanTimeWindowItemModelFromJSON = exports.instanceOfScanTimeWindowItemModel = exports.ScanTimeWindowItemModelDayEnum = void 0;
/**
 * @export
 */
exports.ScanTimeWindowItemModelDayEnum = {
    Sunday: 'Sunday',
    Monday: 'Monday',
    Tuesday: 'Tuesday',
    Wednesday: 'Wednesday',
    Thursday: 'Thursday',
    Friday: 'Friday',
    Saturday: 'Saturday'
};
/**
 * Check if a given object implements the ScanTimeWindowItemModel interface.
 */
function instanceOfScanTimeWindowItemModel(value) {
    return true;
}
exports.instanceOfScanTimeWindowItemModel = instanceOfScanTimeWindowItemModel;
function ScanTimeWindowItemModelFromJSON(json) {
    return ScanTimeWindowItemModelFromJSONTyped(json, false);
}
exports.ScanTimeWindowItemModelFromJSON = ScanTimeWindowItemModelFromJSON;
function ScanTimeWindowItemModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'day': json['Day'] == null ? undefined : json['Day'],
        'from': json['From'] == null ? undefined : json['From'],
        'scanningAllowed': json['ScanningAllowed'] == null ? undefined : json['ScanningAllowed'],
        'to': json['To'] == null ? undefined : json['To'],
    };
}
exports.ScanTimeWindowItemModelFromJSONTyped = ScanTimeWindowItemModelFromJSONTyped;
function ScanTimeWindowItemModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Day': value['day'],
        'From': value['from'],
        'ScanningAllowed': value['scanningAllowed'],
        'To': value['to'],
    };
}
exports.ScanTimeWindowItemModelToJSON = ScanTimeWindowItemModelToJSON;
//# sourceMappingURL=ScanTimeWindowItemModel.js.map