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
import { exists } from '../runtime';
import { AwsConnectionInfoModelFromJSON, AwsConnectionInfoModelToJSON, } from './AwsConnectionInfoModel';
/**
 * @export
 */
export const DiscoveryConnectionsViewModelTypeEnum = {
    Aws: 'Aws'
};
/**
 * Check if a given object implements the DiscoveryConnectionsViewModel interface.
 */
export function instanceOfDiscoveryConnectionsViewModel(value) {
    let isInstance = true;
    isInstance = isInstance && "name" in value;
    return isInstance;
}
export function DiscoveryConnectionsViewModelFromJSON(json) {
    return DiscoveryConnectionsViewModelFromJSONTyped(json, false);
}
export function DiscoveryConnectionsViewModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'name': json['Name'],
        'type': !exists(json, 'Type') ? undefined : json['Type'],
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'awsConnectionInfo': !exists(json, 'AwsConnectionInfo') ? undefined : AwsConnectionInfoModelFromJSON(json['AwsConnectionInfo']),
    };
}
export function DiscoveryConnectionsViewModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Name': value.name,
        'Type': value.type,
        'Id': value.id,
        'AwsConnectionInfo': AwsConnectionInfoModelToJSON(value.awsConnectionInfo),
    };
}
//# sourceMappingURL=DiscoveryConnectionsViewModel.js.map