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
 * Represents a class that carries out basic scan task profile data.
 * @export
 * @interface ReducedScanTaskProfile
 */
export interface ReducedScanTaskProfile {
    /**
     * Gets or sets the identifier.
     * @type {string}
     * @memberof ReducedScanTaskProfile
     */
    id?: string;
    /**
     * Gets or sets a value indicating whether this scan profile is user's profile.
     * @type {boolean}
     * @memberof ReducedScanTaskProfile
     */
    isMine?: boolean;
    /**
     * Gets or sets a value indicating whether this instance is primary scan profile for a website.
     * @type {boolean}
     * @memberof ReducedScanTaskProfile
     */
    isPrimary?: boolean;
    /**
     * Gets or sets a value indicating whether this scan profile is shared to other team members.
     * @type {boolean}
     * @memberof ReducedScanTaskProfile
     */
    isShared?: boolean;
    /**
     * Gets or sets the name.
     * @type {string}
     * @memberof ReducedScanTaskProfile
     */
    name?: string;
    /**
     * Gets or sets the target URL.
     * @type {string}
     * @memberof ReducedScanTaskProfile
     */
    targetUrl?: string;
    /**
     * Gets or sets the Scan Policy name.
     * @type {string}
     * @memberof ReducedScanTaskProfile
     */
    scanPolicyName?: string;
    /**
     * 
     * @type {Array<string>}
     * @memberof ReducedScanTaskProfile
     */
    tags?: Array<string>;
}

/**
 * Check if a given object implements the ReducedScanTaskProfile interface.
 */
export function instanceOfReducedScanTaskProfile(value: object): boolean {
    return true;
}

export function ReducedScanTaskProfileFromJSON(json: any): ReducedScanTaskProfile {
    return ReducedScanTaskProfileFromJSONTyped(json, false);
}

export function ReducedScanTaskProfileFromJSONTyped(json: any, ignoreDiscriminator: boolean): ReducedScanTaskProfile {
    if (json == null) {
        return json;
    }
    return {
        
        'id': json['Id'] == null ? undefined : json['Id'],
        'isMine': json['IsMine'] == null ? undefined : json['IsMine'],
        'isPrimary': json['IsPrimary'] == null ? undefined : json['IsPrimary'],
        'isShared': json['IsShared'] == null ? undefined : json['IsShared'],
        'name': json['Name'] == null ? undefined : json['Name'],
        'targetUrl': json['TargetUrl'] == null ? undefined : json['TargetUrl'],
        'scanPolicyName': json['ScanPolicyName'] == null ? undefined : json['ScanPolicyName'],
        'tags': json['Tags'] == null ? undefined : json['Tags'],
    };
}

export function ReducedScanTaskProfileToJSON(value?: ReducedScanTaskProfile | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Id': value['id'],
        'IsMine': value['isMine'],
        'IsPrimary': value['isPrimary'],
        'IsShared': value['isShared'],
        'Name': value['name'],
        'TargetUrl': value['targetUrl'],
        'ScanPolicyName': value['scanPolicyName'],
        'Tags': value['tags'],
    };
}

