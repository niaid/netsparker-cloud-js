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
 * Contains properties that required to start incremental scheduled scan.
 * @export
 * @interface NewScheduledIncrementalScanApiModel
 */
export interface NewScheduledIncrementalScanApiModel {
    /**
     * Gets or sets a value indicating whether max scan duration is enabled.
     * @type {boolean}
     * @memberof NewScheduledIncrementalScanApiModel
     */
    isMaxScanDurationEnabled?: boolean;
    /**
     * Gets or sets the maximum duration of the scan in hours.
     * @type {number}
     * @memberof NewScheduledIncrementalScanApiModel
     */
    maxScanDuration?: number;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof NewScheduledIncrementalScanApiModel
     */
    name: string;
    /**
     * Gets or sets the next execution time.
     * Date string must be in the same format as in the account settings.
     * @type {string}
     * @memberof NewScheduledIncrementalScanApiModel
     */
    nextExecutionTime: string;
    /**
     * Gets or sets the run interval of scheduled scan.
     * @type {string}
     * @memberof NewScheduledIncrementalScanApiModel
     */
    scheduleRunType: NewScheduledIncrementalScanApiModelScheduleRunTypeEnum;
    /**
     * Gets or sets the tags
     * @type {Array<string>}
     * @memberof NewScheduledIncrementalScanApiModel
     */
    tags?: Array<string>;
    /**
     * Gets or sets the agent name.
     * @type {string}
     * @memberof NewScheduledIncrementalScanApiModel
     */
    agentName?: string;
    /**
     * Gets or sets the base scan identifier.
     * @type {string}
     * @memberof NewScheduledIncrementalScanApiModel
     */
    baseScanId: string;
}

/**
* @export
* @enum {string}
*/
export enum NewScheduledIncrementalScanApiModelScheduleRunTypeEnum {
    Once = 'Once',
    Daily = 'Daily',
    Weekly = 'Weekly',
    Monthly = 'Monthly',
    Quarterly = 'Quarterly',
    Biannually = 'Biannually',
    Yearly = 'Yearly',
    Custom = 'Custom'
}


/**
 * Check if a given object implements the NewScheduledIncrementalScanApiModel interface.
 */
export function instanceOfNewScheduledIncrementalScanApiModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "nextExecutionTime" in value;
    isInstance = isInstance && "scheduleRunType" in value;
    isInstance = isInstance && "baseScanId" in value;

    return isInstance;
}

export function NewScheduledIncrementalScanApiModelFromJSON(json: any): NewScheduledIncrementalScanApiModel {
    return NewScheduledIncrementalScanApiModelFromJSONTyped(json, false);
}

export function NewScheduledIncrementalScanApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): NewScheduledIncrementalScanApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'isMaxScanDurationEnabled': !exists(json, 'IsMaxScanDurationEnabled') ? undefined : json['IsMaxScanDurationEnabled'],
        'maxScanDuration': !exists(json, 'MaxScanDuration') ? undefined : json['MaxScanDuration'],
        'name': json['Name'],
        'nextExecutionTime': json['NextExecutionTime'],
        'scheduleRunType': json['ScheduleRunType'],
        'tags': !exists(json, 'Tags') ? undefined : json['Tags'],
        'agentName': !exists(json, 'AgentName') ? undefined : json['AgentName'],
        'baseScanId': json['BaseScanId'],
    };
}

export function NewScheduledIncrementalScanApiModelToJSON(value?: NewScheduledIncrementalScanApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'IsMaxScanDurationEnabled': value.isMaxScanDurationEnabled,
        'MaxScanDuration': value.maxScanDuration,
        'Name': value.name,
        'NextExecutionTime': value.nextExecutionTime,
        'ScheduleRunType': value.scheduleRunType,
        'Tags': value.tags,
        'AgentName': value.agentName,
        'BaseScanId': value.baseScanId,
    };
}

