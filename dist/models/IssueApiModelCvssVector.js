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
exports.IssueApiModelCvssVectorToJSON = exports.IssueApiModelCvssVectorFromJSONTyped = exports.IssueApiModelCvssVectorFromJSON = exports.instanceOfIssueApiModelCvssVector = void 0;
const runtime_1 = require("../runtime");
const CvssMetricInfo_1 = require("./CvssMetricInfo");
/**
 * Check if a given object implements the IssueApiModelCvssVector interface.
 */
function instanceOfIssueApiModelCvssVector(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfIssueApiModelCvssVector = instanceOfIssueApiModelCvssVector;
function IssueApiModelCvssVectorFromJSON(json) {
    return IssueApiModelCvssVectorFromJSONTyped(json, false);
}
exports.IssueApiModelCvssVectorFromJSON = IssueApiModelCvssVectorFromJSON;
function IssueApiModelCvssVectorFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'base': !(0, runtime_1.exists)(json, 'Base') ? undefined : (0, CvssMetricInfo_1.CvssMetricInfoFromJSON)(json['Base']),
        'temporal': !(0, runtime_1.exists)(json, 'Temporal') ? undefined : (0, CvssMetricInfo_1.CvssMetricInfoFromJSON)(json['Temporal']),
        'environmental': !(0, runtime_1.exists)(json, 'Environmental') ? undefined : (0, CvssMetricInfo_1.CvssMetricInfoFromJSON)(json['Environmental']),
        'threat': !(0, runtime_1.exists)(json, 'Threat') ? undefined : (0, CvssMetricInfo_1.CvssMetricInfoFromJSON)(json['Threat']),
        'supplemental': !(0, runtime_1.exists)(json, 'Supplemental') ? undefined : (0, CvssMetricInfo_1.CvssMetricInfoFromJSON)(json['Supplemental']),
    };
}
exports.IssueApiModelCvssVectorFromJSONTyped = IssueApiModelCvssVectorFromJSONTyped;
function IssueApiModelCvssVectorToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Base': (0, CvssMetricInfo_1.CvssMetricInfoToJSON)(value.base),
        'Temporal': (0, CvssMetricInfo_1.CvssMetricInfoToJSON)(value.temporal),
        'Environmental': (0, CvssMetricInfo_1.CvssMetricInfoToJSON)(value.environmental),
        'Threat': (0, CvssMetricInfo_1.CvssMetricInfoToJSON)(value.threat),
        'Supplemental': (0, CvssMetricInfo_1.CvssMetricInfoToJSON)(value.supplemental),
    };
}
exports.IssueApiModelCvssVectorToJSON = IssueApiModelCvssVectorToJSON;
//# sourceMappingURL=IssueApiModelCvssVector.js.map