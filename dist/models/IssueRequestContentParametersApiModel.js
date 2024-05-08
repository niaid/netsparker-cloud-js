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
exports.IssueRequestContentParametersApiModelToJSON = exports.IssueRequestContentParametersApiModelFromJSONTyped = exports.IssueRequestContentParametersApiModelFromJSON = exports.instanceOfIssueRequestContentParametersApiModel = exports.IssueRequestContentParametersApiModelInputTypeEnum = void 0;
/**
 * @export
 */
exports.IssueRequestContentParametersApiModelInputTypeEnum = {
    Hidden: 'Hidden',
    Text: 'Text',
    Textarea: 'Textarea',
    Submit: 'Submit',
    Reset: 'Reset',
    Button: 'Button',
    Image: 'Image',
    File: 'File',
    Radio: 'Radio',
    Select: 'Select',
    Checkbox: 'Checkbox',
    Password: 'Password',
    Color: 'Color',
    Date: 'Date',
    Datetime: 'Datetime',
    DatetimeLocal: 'DatetimeLocal',
    Email: 'Email',
    Month: 'Month',
    Number: 'Number',
    Range: 'Range',
    Search: 'Search',
    Tel: 'Tel',
    Time: 'Time',
    Url: 'Url',
    Week: 'Week',
    Output: 'Output'
};
/**
 * Check if a given object implements the IssueRequestContentParametersApiModel interface.
 */
function instanceOfIssueRequestContentParametersApiModel(value) {
    return true;
}
exports.instanceOfIssueRequestContentParametersApiModel = instanceOfIssueRequestContentParametersApiModel;
function IssueRequestContentParametersApiModelFromJSON(json) {
    return IssueRequestContentParametersApiModelFromJSONTyped(json, false);
}
exports.IssueRequestContentParametersApiModelFromJSON = IssueRequestContentParametersApiModelFromJSON;
function IssueRequestContentParametersApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'name': json['Name'] == null ? undefined : json['Name'],
        'value': json['Value'] == null ? undefined : json['Value'],
        'typeName': json['TypeName'] == null ? undefined : json['TypeName'],
        'inputType': json['InputType'] == null ? undefined : json['InputType'],
    };
}
exports.IssueRequestContentParametersApiModelFromJSONTyped = IssueRequestContentParametersApiModelFromJSONTyped;
function IssueRequestContentParametersApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Name': value['name'],
        'Value': value['value'],
        'TypeName': value['typeName'],
        'InputType': value['inputType'],
    };
}
exports.IssueRequestContentParametersApiModelToJSON = IssueRequestContentParametersApiModelToJSON;
//# sourceMappingURL=IssueRequestContentParametersApiModel.js.map