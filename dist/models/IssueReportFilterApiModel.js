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
exports.IssueReportFilterApiModelToJSON = exports.IssueReportFilterApiModelFromJSONTyped = exports.IssueReportFilterApiModelFromJSON = exports.instanceOfIssueReportFilterApiModel = exports.IssueReportFilterApiModelSeverityEnum = exports.IssueReportFilterApiModelCsvSeparatorEnum = void 0;
/**
 * @export
 */
exports.IssueReportFilterApiModelCsvSeparatorEnum = {
    Comma: 'Comma',
    Semicolon: 'Semicolon',
    Pipe: 'Pipe',
    Tab: 'Tab'
};
/**
 * @export
 */
exports.IssueReportFilterApiModelSeverityEnum = {
    BestPractice: 'BestPractice',
    Information: 'Information',
    Low: 'Low',
    Medium: 'Medium',
    High: 'High',
    Critical: 'Critical'
};
/**
 * Check if a given object implements the IssueReportFilterApiModel interface.
 */
function instanceOfIssueReportFilterApiModel(value) {
    return true;
}
exports.instanceOfIssueReportFilterApiModel = instanceOfIssueReportFilterApiModel;
function IssueReportFilterApiModelFromJSON(json) {
    return IssueReportFilterApiModelFromJSONTyped(json, false);
}
exports.IssueReportFilterApiModelFromJSON = IssueReportFilterApiModelFromJSON;
function IssueReportFilterApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'csvSeparator': json['CsvSeparator'] == null ? undefined : json['CsvSeparator'],
        'severity': json['Severity'] == null ? undefined : json['Severity'],
        'websiteGroupName': json['WebsiteGroupName'] == null ? undefined : json['WebsiteGroupName'],
        'webSiteName': json['WebSiteName'] == null ? undefined : json['WebSiteName'],
        'startDate': json['StartDate'] == null ? undefined : (new Date(json['StartDate'])),
        'endDate': json['EndDate'] == null ? undefined : (new Date(json['EndDate'])),
    };
}
exports.IssueReportFilterApiModelFromJSONTyped = IssueReportFilterApiModelFromJSONTyped;
function IssueReportFilterApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'CsvSeparator': value['csvSeparator'],
        'Severity': value['severity'],
        'WebsiteGroupName': value['websiteGroupName'],
        'WebSiteName': value['webSiteName'],
        'StartDate': value['startDate'] == null ? undefined : ((value['startDate']).toISOString()),
        'EndDate': value['endDate'] == null ? undefined : ((value['endDate']).toISOString()),
    };
}
exports.IssueReportFilterApiModelToJSON = IssueReportFilterApiModelToJSON;
//# sourceMappingURL=IssueReportFilterApiModel.js.map