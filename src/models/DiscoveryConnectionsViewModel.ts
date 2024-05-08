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
import type { AwsConnectionInfoModel } from './AwsConnectionInfoModel';
import {
    AwsConnectionInfoModelFromJSON,
    AwsConnectionInfoModelFromJSONTyped,
    AwsConnectionInfoModelToJSON,
} from './AwsConnectionInfoModel';

/**
 * 
 * @export
 * @interface DiscoveryConnectionsViewModel
 */
export interface DiscoveryConnectionsViewModel {
    /**
     * 
     * @type {string}
     * @memberof DiscoveryConnectionsViewModel
     */
    name: string;
    /**
     * Gets or sets ConnectionType type.
     * @type {string}
     * @memberof DiscoveryConnectionsViewModel
     */
    type?: DiscoveryConnectionsViewModelTypeEnum;
    /**
     * Gets or sets the identifier.
     * @type {string}
     * @memberof DiscoveryConnectionsViewModel
     */
    id?: string;
    /**
     * 
     * @type {AwsConnectionInfoModel}
     * @memberof DiscoveryConnectionsViewModel
     */
    awsConnectionInfo?: AwsConnectionInfoModel;
}


/**
 * @export
 */
export const DiscoveryConnectionsViewModelTypeEnum = {
    Aws: 'Aws'
} as const;
export type DiscoveryConnectionsViewModelTypeEnum = typeof DiscoveryConnectionsViewModelTypeEnum[keyof typeof DiscoveryConnectionsViewModelTypeEnum];


/**
 * Check if a given object implements the DiscoveryConnectionsViewModel interface.
 */
export function instanceOfDiscoveryConnectionsViewModel(value: object): boolean {
    if (!('name' in value)) return false;
    return true;
}

export function DiscoveryConnectionsViewModelFromJSON(json: any): DiscoveryConnectionsViewModel {
    return DiscoveryConnectionsViewModelFromJSONTyped(json, false);
}

export function DiscoveryConnectionsViewModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): DiscoveryConnectionsViewModel {
    if (json == null) {
        return json;
    }
    return {
        
        'name': json['Name'],
        'type': json['Type'] == null ? undefined : json['Type'],
        'id': json['Id'] == null ? undefined : json['Id'],
        'awsConnectionInfo': json['AwsConnectionInfo'] == null ? undefined : AwsConnectionInfoModelFromJSON(json['AwsConnectionInfo']),
    };
}

export function DiscoveryConnectionsViewModelToJSON(value?: DiscoveryConnectionsViewModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'Name': value['name'],
        'Type': value['type'],
        'Id': value['id'],
        'AwsConnectionInfo': AwsConnectionInfoModelToJSON(value['awsConnectionInfo']),
    };
}

