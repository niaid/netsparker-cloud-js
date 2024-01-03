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
import { exists } from '../runtime';
/**
 * @export
 */
export const IssueRequestContentParametersApiModelInputTypeEnum = {
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
export function instanceOfIssueRequestContentParametersApiModel(value) {
    let isInstance = true;
    return isInstance;
}
export function IssueRequestContentParametersApiModelFromJSON(json) {
    return IssueRequestContentParametersApiModelFromJSONTyped(json, false);
}
export function IssueRequestContentParametersApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'name': !exists(json, 'Name') ? undefined : json['Name'],
        'value': !exists(json, 'Value') ? undefined : json['Value'],
        'typeName': !exists(json, 'TypeName') ? undefined : json['TypeName'],
        'inputType': !exists(json, 'InputType') ? undefined : json['InputType'],
    };
}
export function IssueRequestContentParametersApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Name': value.name,
        'Value': value.value,
        'TypeName': value.typeName,
        'InputType': value.inputType,
    };
}
//# sourceMappingURL=IssueRequestContentParametersApiModel.js.map