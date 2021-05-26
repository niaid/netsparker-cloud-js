"use strict";
/**
 * Netsparker Enterprise API
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
exports.CvssScoreValue = void 0;
class CvssScoreValue {
    static getAttributeTypeMap() {
        return CvssScoreValue.attributeTypeMap;
    }
}
exports.CvssScoreValue = CvssScoreValue;
CvssScoreValue.discriminator = undefined;
CvssScoreValue.attributeTypeMap = [
    {
        "name": "severity",
        "baseName": "Severity",
        "type": "CvssScoreValue.SeverityEnum"
    },
    {
        "name": "value",
        "baseName": "Value",
        "type": "number"
    }
];
(function (CvssScoreValue) {
    let SeverityEnum;
    (function (SeverityEnum) {
        SeverityEnum[SeverityEnum["None"] = 'None'] = "None";
        SeverityEnum[SeverityEnum["Low"] = 'Low'] = "Low";
        SeverityEnum[SeverityEnum["Medium"] = 'Medium'] = "Medium";
        SeverityEnum[SeverityEnum["High"] = 'High'] = "High";
        SeverityEnum[SeverityEnum["Critical"] = 'Critical'] = "Critical";
    })(SeverityEnum = CvssScoreValue.SeverityEnum || (CvssScoreValue.SeverityEnum = {}));
})(CvssScoreValue = exports.CvssScoreValue || (exports.CvssScoreValue = {}));
//# sourceMappingURL=cvssScoreValue.js.map