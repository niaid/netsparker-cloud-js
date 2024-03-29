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
 * Represents a model for carrying out an update incremental scan notification data
 * @export
 * @interface UpdateScheduledIncrementalScanApiModel
 */
export interface UpdateScheduledIncrementalScanApiModel {
    /**
     * Gets or sets a value indicating whether scheduled scan is disabled.
     * @type {boolean}
     * @memberof UpdateScheduledIncrementalScanApiModel
     */
    disabled?: boolean;
    /**
     * Gets or sets the scan identifier.
     * @type {string}
     * @memberof UpdateScheduledIncrementalScanApiModel
     */
    id: string;
    /**
     * Gets or sets a value indicating whether max scan duration is enabled.
     * @type {boolean}
     * @memberof UpdateScheduledIncrementalScanApiModel
     */
    isMaxScanDurationEnabled?: boolean;
    /**
     * Gets or sets the maximum duration of the scan in hours.
     * @type {number}
     * @memberof UpdateScheduledIncrementalScanApiModel
     */
    maxScanDuration?: number;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof UpdateScheduledIncrementalScanApiModel
     */
    name: string;
    /**
     * Gets or sets the next execution time.
     * Date string must be in the same format as in the account settings.
     * @type {string}
     * @memberof UpdateScheduledIncrementalScanApiModel
     */
    nextExecutionTime: string;
    /**
     * Gets or sets the run interval of scheduled scan.
     * @type {string}
     * @memberof UpdateScheduledIncrementalScanApiModel
     */
    scheduleRunType: UpdateScheduledIncrementalScanApiModelScheduleRunTypeEnum;
    /**
     * Gets or sets the tags
     * @type {Array<string>}
     * @memberof UpdateScheduledIncrementalScanApiModel
     */
    tags?: Array<string>;
    /**
     * Gets or sets the agent name.
     * @type {string}
     * @memberof UpdateScheduledIncrementalScanApiModel
     */
    agentName?: string;
    /**
     * Gets or sets the base scan identifier.
     * @type {string}
     * @memberof UpdateScheduledIncrementalScanApiModel
     */
    baseScanId: string;
}


/**
 * @export
 */
export const UpdateScheduledIncrementalScanApiModelScheduleRunTypeEnum = {
    Once: 'Once',
    Daily: 'Daily',
    Weekly: 'Weekly',
    Monthly: 'Monthly',
    Quarterly: 'Quarterly',
    Biannually: 'Biannually',
    Yearly: 'Yearly',
    Custom: 'Custom'
} as const;
export type UpdateScheduledIncrementalScanApiModelScheduleRunTypeEnum = typeof UpdateScheduledIncrementalScanApiModelScheduleRunTypeEnum[keyof typeof UpdateScheduledIncrementalScanApiModelScheduleRunTypeEnum];


/**
 * Check if a given object implements the UpdateScheduledIncrementalScanApiModel interface.
 */
export function instanceOfUpdateScheduledIncrementalScanApiModel(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "id" in value;
    isInstance = isInstance && "name" in value;
    isInstance = isInstance && "nextExecutionTime" in value;
    isInstance = isInstance && "scheduleRunType" in value;
    isInstance = isInstance && "baseScanId" in value;

    return isInstance;
}

export function UpdateScheduledIncrementalScanApiModelFromJSON(json: any): UpdateScheduledIncrementalScanApiModel {
    return UpdateScheduledIncrementalScanApiModelFromJSONTyped(json, false);
}

export function UpdateScheduledIncrementalScanApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateScheduledIncrementalScanApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'disabled': !exists(json, 'Disabled') ? undefined : json['Disabled'],
        'id': json['Id'],
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

export function UpdateScheduledIncrementalScanApiModelToJSON(value?: UpdateScheduledIncrementalScanApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Disabled': value.disabled,
        'Id': value.id,
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

