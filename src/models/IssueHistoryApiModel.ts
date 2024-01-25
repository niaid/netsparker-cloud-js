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
    let isInstance = true;

    return isInstance;
}

export function IssueHistoryApiModelFromJSON(json: any): IssueHistoryApiModel {
    return IssueHistoryApiModelFromJSONTyped(json, false);
}

export function IssueHistoryApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): IssueHistoryApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'message': !exists(json, 'Message') ? undefined : json['Message'],
        'note': !exists(json, 'Note') ? undefined : json['Note'],
        'owner': !exists(json, 'Owner') ? undefined : json['Owner'],
        'date': !exists(json, 'Date') ? undefined : json['Date'],
    };
}

export function IssueHistoryApiModelToJSON(value?: IssueHistoryApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Message': value.message,
        'Note': value.note,
        'Owner': value.owner,
        'Date': value.date,
    };
}

