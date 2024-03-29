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

import { exists, mapValues } from '../runtime';
/**
 * Issue request content parameters api response mapping class.
 * @export
 * @interface IssueRequestContentParametersApiModel
 */
export interface IssueRequestContentParametersApiModel {
    /**
     * Gets or sets the parameter name
     * @type {string}
     * @memberof IssueRequestContentParametersApiModel
     */
    name?: string;
    /**
     * Gets or sets the parameter value
     * @type {string}
     * @memberof IssueRequestContentParametersApiModel
     */
    value?: string;
    /**
     * Gets or sets the parameter type name
     * @type {string}
     * @memberof IssueRequestContentParametersApiModel
     */
    typeName?: string;
    /**
     * Gets or sets the input type
     * @type {string}
     * @memberof IssueRequestContentParametersApiModel
     */
    inputType?: IssueRequestContentParametersApiModelInputTypeEnum;
}


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
} as const;
export type IssueRequestContentParametersApiModelInputTypeEnum = typeof IssueRequestContentParametersApiModelInputTypeEnum[keyof typeof IssueRequestContentParametersApiModelInputTypeEnum];


/**
 * Check if a given object implements the IssueRequestContentParametersApiModel interface.
 */
export function instanceOfIssueRequestContentParametersApiModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function IssueRequestContentParametersApiModelFromJSON(json: any): IssueRequestContentParametersApiModel {
    return IssueRequestContentParametersApiModelFromJSONTyped(json, false);
}

export function IssueRequestContentParametersApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): IssueRequestContentParametersApiModel {
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

export function IssueRequestContentParametersApiModelToJSON(value?: IssueRequestContentParametersApiModel | null): any {
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

