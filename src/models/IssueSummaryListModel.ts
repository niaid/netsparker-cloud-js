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
import type { IssueSummaryStatusModel } from './IssueSummaryStatusModel';
import {
    IssueSummaryStatusModelFromJSON,
    IssueSummaryStatusModelFromJSONTyped,
    IssueSummaryStatusModelToJSON,
} from './IssueSummaryStatusModel';

/**
 * 
 * @export
 * @interface IssueSummaryListModel
 */
export interface IssueSummaryListModel {
    /**
     * Gets or sets Vulnerability Title
     * @type {string}
     * @memberof IssueSummaryListModel
     */
    title?: string;
    /**
     * Gets or sets Vulnerability State
     * @type {string}
     * @memberof IssueSummaryListModel
     */
    state?: IssueSummaryListModelStateEnum;
    /**
     * Gets or sets Vulnerability Severity
     * @type {string}
     * @memberof IssueSummaryListModel
     */
    severity?: IssueSummaryListModelSeverityEnum;
    /**
     * Gets or sets Vulnerability Url
     * @type {string}
     * @memberof IssueSummaryListModel
     */
    url?: string;
    /**
     * Gets or sets list of Vulnerability Status by date
     * @type {Array<IssueSummaryStatusModel>}
     * @memberof IssueSummaryListModel
     */
    statusByDate?: Array<IssueSummaryStatusModel>;
}


/**
 * @export
 */
export const IssueSummaryListModelStateEnum = {
    Present: 'Present',
    FixedUnconfirmed: 'FixedUnconfirmed',
    FixedCantRetest: 'FixedCantRetest',
    FixedConfirmed: 'FixedConfirmed',
    Revived: 'Revived',
    Scanning: 'Scanning',
    Ignored: 'Ignored',
    AcceptedRisk: 'AcceptedRisk',
    FalsePositive: 'FalsePositive'
} as const;
export type IssueSummaryListModelStateEnum = typeof IssueSummaryListModelStateEnum[keyof typeof IssueSummaryListModelStateEnum];

/**
 * @export
 */
export const IssueSummaryListModelSeverityEnum = {
    BestPractice: 'BestPractice',
    Information: 'Information',
    Low: 'Low',
    Medium: 'Medium',
    High: 'High',
    Critical: 'Critical'
} as const;
export type IssueSummaryListModelSeverityEnum = typeof IssueSummaryListModelSeverityEnum[keyof typeof IssueSummaryListModelSeverityEnum];


/**
 * Check if a given object implements the IssueSummaryListModel interface.
 */
export function instanceOfIssueSummaryListModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function IssueSummaryListModelFromJSON(json: any): IssueSummaryListModel {
    return IssueSummaryListModelFromJSONTyped(json, false);
}

export function IssueSummaryListModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): IssueSummaryListModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'title': !exists(json, 'Title') ? undefined : json['Title'],
        'state': !exists(json, 'State') ? undefined : json['State'],
        'severity': !exists(json, 'Severity') ? undefined : json['Severity'],
        'url': !exists(json, 'Url') ? undefined : json['Url'],
        'statusByDate': !exists(json, 'StatusByDate') ? undefined : ((json['StatusByDate'] as Array<any>).map(IssueSummaryStatusModelFromJSON)),
    };
}

export function IssueSummaryListModelToJSON(value?: IssueSummaryListModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Title': value.title,
        'State': value.state,
        'Severity': value.severity,
        'Url': value.url,
        'StatusByDate': value.statusByDate === undefined ? undefined : ((value.statusByDate as Array<any>).map(IssueSummaryStatusModelToJSON)),
    };
}

