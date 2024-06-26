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
 * Pci Scan Task view model
 * @export
 * @interface PciScanTaskViewModel
 */
export interface PciScanTaskViewModel {
    /**
     * Gets or sets the name
     * @type {string}
     * @memberof PciScanTaskViewModel
     */
    name?: string;
    /**
     * Gets or sets the progress for scan task
     * @type {number}
     * @memberof PciScanTaskViewModel
     */
    progress?: number;
    /**
     * Gets or sets the scan state
     * @type {string}
     * @memberof PciScanTaskViewModel
     */
    scanState?: PciScanTaskViewModelScanStateEnum;
    /**
     * Gets or sets the compliance status. This will be setted when pci scan task is done
     * @type {string}
     * @memberof PciScanTaskViewModel
     */
    complianceStatus?: PciScanTaskViewModelComplianceStatusEnum;
    /**
     * Gets or sets the end date
     * @type {Date}
     * @memberof PciScanTaskViewModel
     */
    endDate?: Date;
}


/**
 * @export
 */
export const PciScanTaskViewModelScanStateEnum = {
    New: 'New',
    Running: 'Running',
    Stopped: 'Stopped',
    Deleted: 'Deleted',
    Done: 'Done'
} as const;
export type PciScanTaskViewModelScanStateEnum = typeof PciScanTaskViewModelScanStateEnum[keyof typeof PciScanTaskViewModelScanStateEnum];

/**
 * @export
 */
export const PciScanTaskViewModelComplianceStatusEnum = {
    Scanning: 'Scanning',
    Passed: 'Passed',
    Failed: 'Failed'
} as const;
export type PciScanTaskViewModelComplianceStatusEnum = typeof PciScanTaskViewModelComplianceStatusEnum[keyof typeof PciScanTaskViewModelComplianceStatusEnum];


/**
 * Check if a given object implements the PciScanTaskViewModel interface.
 */
export function instanceOfPciScanTaskViewModel(value: object): boolean {
    return true;
}

export function PciScanTaskViewModelFromJSON(json: any): PciScanTaskViewModel {
    return PciScanTaskViewModelFromJSONTyped(json, false);
}

export function PciScanTaskViewModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): PciScanTaskViewModel {
    if (json == null) {
        return json;
    }
    return {
        
        'name': json['Name'] == null ? undefined : json['Name'],
        'progress': json['Progress'] == null ? undefined : json['Progress'],
        'scanState': json['ScanState'] == null ? undefined : json['ScanState'],
        'complianceStatus': json['ComplianceStatus'] == null ? undefined : json['ComplianceStatus'],
        'endDate': json['EndDate'] == null ? undefined : (new Date(json['EndDate'])),
    };
}

export function PciScanTaskViewModelToJSON(value?: PciScanTaskViewModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Name': value['name'],
        'Progress': value['progress'],
        'ScanState': value['scanState'],
        'ComplianceStatus': value['complianceStatus'],
        'EndDate': value['endDate'] == null ? undefined : ((value['endDate']).toISOString()),
    };
}

