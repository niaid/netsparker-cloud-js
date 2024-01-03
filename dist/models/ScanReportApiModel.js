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
exports.ScanReportApiModelToJSON = exports.ScanReportApiModelFromJSONTyped = exports.ScanReportApiModelFromJSON = exports.instanceOfScanReportApiModel = exports.ScanReportApiModelTypeEnum = exports.ScanReportApiModelFormatEnum = exports.ScanReportApiModelContentFormatEnum = void 0;
const runtime_1 = require("../runtime");
/**
* @export
* @enum {string}
*/
var ScanReportApiModelContentFormatEnum;
(function (ScanReportApiModelContentFormatEnum) {
    ScanReportApiModelContentFormatEnum["Html"] = "Html";
    ScanReportApiModelContentFormatEnum["Markdown"] = "Markdown";
})(ScanReportApiModelContentFormatEnum = exports.ScanReportApiModelContentFormatEnum || (exports.ScanReportApiModelContentFormatEnum = {}));
/**
* @export
* @enum {string}
*/
var ScanReportApiModelFormatEnum;
(function (ScanReportApiModelFormatEnum) {
    ScanReportApiModelFormatEnum["Xml"] = "Xml";
    ScanReportApiModelFormatEnum["Csv"] = "Csv";
    ScanReportApiModelFormatEnum["Pdf"] = "Pdf";
    ScanReportApiModelFormatEnum["Html"] = "Html";
    ScanReportApiModelFormatEnum["Txt"] = "Txt";
    ScanReportApiModelFormatEnum["Json"] = "Json";
})(ScanReportApiModelFormatEnum = exports.ScanReportApiModelFormatEnum || (exports.ScanReportApiModelFormatEnum = {}));
/**
* @export
* @enum {string}
*/
var ScanReportApiModelTypeEnum;
(function (ScanReportApiModelTypeEnum) {
    ScanReportApiModelTypeEnum["Crawled"] = "Crawled";
    ScanReportApiModelTypeEnum["Scanned"] = "Scanned";
    ScanReportApiModelTypeEnum["Vulnerabilities"] = "Vulnerabilities";
    ScanReportApiModelTypeEnum["ScanDetail"] = "ScanDetail";
    ScanReportApiModelTypeEnum["ModSecurityWafRules"] = "ModSecurityWafRules";
    ScanReportApiModelTypeEnum["OwaspTopTen2013"] = "OwaspTopTen2013";
    ScanReportApiModelTypeEnum["HipaaCompliance"] = "HIPAACompliance";
    ScanReportApiModelTypeEnum["Pci32"] = "Pci32";
    ScanReportApiModelTypeEnum["KnowledgeBase"] = "KnowledgeBase";
    ScanReportApiModelTypeEnum["ExecutiveSummary"] = "ExecutiveSummary";
    ScanReportApiModelTypeEnum["FullScanDetail"] = "FullScanDetail";
    ScanReportApiModelTypeEnum["OwaspTopTen2017"] = "OwaspTopTen2017";
    ScanReportApiModelTypeEnum["CustomReport"] = "CustomReport";
    ScanReportApiModelTypeEnum["Iso27001Compliance"] = "Iso27001Compliance";
    ScanReportApiModelTypeEnum["F5BigIpAsmWafRules"] = "F5BigIpAsmWafRules";
    ScanReportApiModelTypeEnum["Wasc"] = "WASC";
    ScanReportApiModelTypeEnum["SansTop25"] = "SansTop25";
    ScanReportApiModelTypeEnum["Asvs40"] = "Asvs40";
    ScanReportApiModelTypeEnum["Nistsp80053"] = "Nistsp80053";
    ScanReportApiModelTypeEnum["DisaStig"] = "DisaStig";
    ScanReportApiModelTypeEnum["OwaspApiTop10"] = "OwaspApiTop10";
    ScanReportApiModelTypeEnum["OwaspTopTen2021"] = "OwaspTopTen2021";
    ScanReportApiModelTypeEnum["VulnerabilitiesPerWebsite"] = "VulnerabilitiesPerWebsite";
    ScanReportApiModelTypeEnum["OwaspApiTopTen2023"] = "OwaspApiTopTen2023";
    ScanReportApiModelTypeEnum["PciDss40"] = "PciDss40";
})(ScanReportApiModelTypeEnum = exports.ScanReportApiModelTypeEnum || (exports.ScanReportApiModelTypeEnum = {}));
/**
 * Check if a given object implements the ScanReportApiModel interface.
 */
function instanceOfScanReportApiModel(value) {
    let isInstance = true;
    isInstance = isInstance && "format" in value;
    isInstance = isInstance && "id" in value;
    isInstance = isInstance && "type" in value;
    return isInstance;
}
exports.instanceOfScanReportApiModel = instanceOfScanReportApiModel;
function ScanReportApiModelFromJSON(json) {
    return ScanReportApiModelFromJSONTyped(json, false);
}
exports.ScanReportApiModelFromJSON = ScanReportApiModelFromJSON;
function ScanReportApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'contentFormat': !(0, runtime_1.exists)(json, 'ContentFormat') ? undefined : json['ContentFormat'],
        'excludeResponseData': !(0, runtime_1.exists)(json, 'ExcludeResponseData') ? undefined : json['ExcludeResponseData'],
        'format': json['Format'],
        'id': json['Id'],
        'type': json['Type'],
        'onlyConfirmedIssues': !(0, runtime_1.exists)(json, 'OnlyConfirmedIssues') ? undefined : json['OnlyConfirmedIssues'],
        'onlyUnconfirmedIssues': !(0, runtime_1.exists)(json, 'OnlyUnconfirmedIssues') ? undefined : json['OnlyUnconfirmedIssues'],
        'excludeAddressedIssues': !(0, runtime_1.exists)(json, 'ExcludeAddressedIssues') ? undefined : json['ExcludeAddressedIssues'],
        'excludeHistoryOfIssues': !(0, runtime_1.exists)(json, 'ExcludeHistoryOfIssues') ? undefined : json['ExcludeHistoryOfIssues'],
    };
}
exports.ScanReportApiModelFromJSONTyped = ScanReportApiModelFromJSONTyped;
function ScanReportApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'ContentFormat': value.contentFormat,
        'ExcludeResponseData': value.excludeResponseData,
        'Format': value.format,
        'Id': value.id,
        'Type': value.type,
        'OnlyConfirmedIssues': value.onlyConfirmedIssues,
        'OnlyUnconfirmedIssues': value.onlyUnconfirmedIssues,
        'ExcludeAddressedIssues': value.excludeAddressedIssues,
        'ExcludeHistoryOfIssues': value.excludeHistoryOfIssues,
    };
}
exports.ScanReportApiModelToJSON = ScanReportApiModelToJSON;
//# sourceMappingURL=ScanReportApiModel.js.map