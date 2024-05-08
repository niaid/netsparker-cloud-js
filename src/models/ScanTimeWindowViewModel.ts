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
import type { ScanTimeWindowItemViewModel } from './ScanTimeWindowItemViewModel';
import {
    ScanTimeWindowItemViewModelFromJSON,
    ScanTimeWindowItemViewModelFromJSONTyped,
    ScanTimeWindowItemViewModelToJSON,
} from './ScanTimeWindowItemViewModel';

/**
 * Represents a model for carrying out scan time window settings.
 * @export
 * @interface ScanTimeWindowViewModel
 */
export interface ScanTimeWindowViewModel {
    /**
     * Gets or sets a value indicating whether scan time window is enabled.
     * @type {boolean}
     * @memberof ScanTimeWindowViewModel
     */
    isEnabled?: boolean;
    /**
     * Gets or sets a value indicating whether scan time window is enabled.
     * @type {boolean}
     * @memberof ScanTimeWindowViewModel
     */
    isEnabledForWebsite?: boolean;
    /**
     * Gets or sets a value indicating whether scan time window is enabled.
     * @type {boolean}
     * @memberof ScanTimeWindowViewModel
     */
    isEnabledForWebsiteGroup?: boolean;
    /**
     * Gets or sets the time range items.
     * @type {Array<ScanTimeWindowItemViewModel>}
     * @memberof ScanTimeWindowViewModel
     */
    items?: Array<ScanTimeWindowItemViewModel>;
    /**
     * Scan time window created time zone.
     * @type {string}
     * @memberof ScanTimeWindowViewModel
     */
    timeZone?: string;
    /**
     * Gets or sets the scan create type.
     * @type {string}
     * @memberof ScanTimeWindowViewModel
     */
    scanCreateType?: ScanTimeWindowViewModelScanCreateTypeEnum;
}


/**
 * @export
 */
export const ScanTimeWindowViewModelScanCreateTypeEnum = {
    Website: 'Website',
    WebsiteGroup: 'WebsiteGroup'
} as const;
export type ScanTimeWindowViewModelScanCreateTypeEnum = typeof ScanTimeWindowViewModelScanCreateTypeEnum[keyof typeof ScanTimeWindowViewModelScanCreateTypeEnum];


/**
 * Check if a given object implements the ScanTimeWindowViewModel interface.
 */
export function instanceOfScanTimeWindowViewModel(value: object): boolean {
    return true;
}

export function ScanTimeWindowViewModelFromJSON(json: any): ScanTimeWindowViewModel {
    return ScanTimeWindowViewModelFromJSONTyped(json, false);
}

export function ScanTimeWindowViewModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScanTimeWindowViewModel {
    if (json == null) {
        return json;
    }
    return {
        
        'isEnabled': json['IsEnabled'] == null ? undefined : json['IsEnabled'],
        'isEnabledForWebsite': json['IsEnabledForWebsite'] == null ? undefined : json['IsEnabledForWebsite'],
        'isEnabledForWebsiteGroup': json['IsEnabledForWebsiteGroup'] == null ? undefined : json['IsEnabledForWebsiteGroup'],
        'items': json['Items'] == null ? undefined : ((json['Items'] as Array<any>).map(ScanTimeWindowItemViewModelFromJSON)),
        'timeZone': json['TimeZone'] == null ? undefined : json['TimeZone'],
        'scanCreateType': json['ScanCreateType'] == null ? undefined : json['ScanCreateType'],
    };
}

export function ScanTimeWindowViewModelToJSON(value?: ScanTimeWindowViewModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'IsEnabled': value['isEnabled'],
        'IsEnabledForWebsite': value['isEnabledForWebsite'],
        'IsEnabledForWebsiteGroup': value['isEnabledForWebsiteGroup'],
        'Items': value['items'] == null ? undefined : ((value['items'] as Array<any>).map(ScanTimeWindowItemViewModelToJSON)),
        'TimeZone': value['timeZone'],
        'ScanCreateType': value['scanCreateType'],
    };
}

