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
 * Represents a model for carrying out scan status data for API.
 * @export
 * @interface ApiScanStatusModel
 */
export interface ApiScanStatusModel {
    /**
     * Gets or sets the completed steps.
     * @type {number}
     * @memberof ApiScanStatusModel
     */
    completedSteps?: number;
    /**
     * Gets or sets the estimated launch time in minutes for queued scans.
     * @type {number}
     * @memberof ApiScanStatusModel
     */
    estimatedLaunchTime?: number;
    /**
     * Gets or sets the estimated steps.
     * @type {number}
     * @memberof ApiScanStatusModel
     */
    estimatedSteps?: number;
    /**
     * Gets or sets the state.
     * @type {string}
     * @memberof ApiScanStatusModel
     */
    state?: ApiScanStatusModelStateEnum;
}


/**
 * @export
 */
export const ApiScanStatusModelStateEnum = {
    Queued: 'Queued',
    Scanning: 'Scanning',
    Archiving: 'Archiving',
    Complete: 'Complete',
    Failed: 'Failed',
    Cancelled: 'Cancelled',
    Delayed: 'Delayed',
    Pausing: 'Pausing',
    Paused: 'Paused',
    Resuming: 'Resuming',
    AsyncArchiving: 'AsyncArchiving'
} as const;
export type ApiScanStatusModelStateEnum = typeof ApiScanStatusModelStateEnum[keyof typeof ApiScanStatusModelStateEnum];


/**
 * Check if a given object implements the ApiScanStatusModel interface.
 */
export function instanceOfApiScanStatusModel(value: object): boolean {
    return true;
}

export function ApiScanStatusModelFromJSON(json: any): ApiScanStatusModel {
    return ApiScanStatusModelFromJSONTyped(json, false);
}

export function ApiScanStatusModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ApiScanStatusModel {
    if (json == null) {
        return json;
    }
    return {
        
        'completedSteps': json['CompletedSteps'] == null ? undefined : json['CompletedSteps'],
        'estimatedLaunchTime': json['EstimatedLaunchTime'] == null ? undefined : json['EstimatedLaunchTime'],
        'estimatedSteps': json['EstimatedSteps'] == null ? undefined : json['EstimatedSteps'],
        'state': json['State'] == null ? undefined : json['State'],
    };
}

export function ApiScanStatusModelToJSON(value?: ApiScanStatusModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'CompletedSteps': value['completedSteps'],
        'EstimatedLaunchTime': value['estimatedLaunchTime'],
        'EstimatedSteps': value['estimatedSteps'],
        'State': value['state'],
    };
}

