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

import { mapValues } from '../runtime';
/**
 * Model for issue api history prop
 * @export
 * @interface IssueHistoryApiModel
 */
export interface IssueHistoryApiModel {
    /**
     * Message to display
     * @type {string}
     * @memberof IssueHistoryApiModel
     */
    message?: string;
    /**
     * Note to display
     * @type {string}
     * @memberof IssueHistoryApiModel
     */
    note?: string;
    /**
     * Owner of event
     * @type {string}
     * @memberof IssueHistoryApiModel
     */
    owner?: string;
    /**
     * Date of event
     * @type {string}
     * @memberof IssueHistoryApiModel
     */
    date?: string;
}

/**
 * Check if a given object implements the IssueHistoryApiModel interface.
 */
export function instanceOfIssueHistoryApiModel(value: object): boolean {
    return true;
}

export function IssueHistoryApiModelFromJSON(json: any): IssueHistoryApiModel {
    return IssueHistoryApiModelFromJSONTyped(json, false);
}

export function IssueHistoryApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): IssueHistoryApiModel {
    if (json == null) {
        return json;
    }
    return {
        
        'message': json['Message'] == null ? undefined : json['Message'],
        'note': json['Note'] == null ? undefined : json['Note'],
        'owner': json['Owner'] == null ? undefined : json['Owner'],
        'date': json['Date'] == null ? undefined : json['Date'],
    };
}

export function IssueHistoryApiModelToJSON(value?: IssueHistoryApiModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Message': value['message'],
        'Note': value['note'],
        'Owner': value['owner'],
        'Date': value['date'],
    };
}

