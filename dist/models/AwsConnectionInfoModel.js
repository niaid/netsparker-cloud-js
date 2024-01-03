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
/**
 * Check if a given object implements the AwsConnectionInfoModel interface.
 */
export function instanceOfAwsConnectionInfoModel(value) {
    let isInstance = true;
    isInstance = isInstance && "region" in value;
    isInstance = isInstance && "accessKeyId" in value;
    isInstance = isInstance && "secretAccessKey" in value;
    return isInstance;
}
export function AwsConnectionInfoModelFromJSON(json) {
    return AwsConnectionInfoModelFromJSONTyped(json, false);
}
export function AwsConnectionInfoModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'region': json['Region'],
        'accessKeyId': json['AccessKeyId'],
        'secretAccessKey': json['SecretAccessKey'],
        'showUnreachableDiscoveredWebsites': !exists(json, 'ShowUnreachableDiscoveredWebsites') ? undefined : json['ShowUnreachableDiscoveredWebsites'],
    };
}
export function AwsConnectionInfoModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Region': value.region,
        'AccessKeyId': value.accessKeyId,
        'SecretAccessKey': value.secretAccessKey,
        'ShowUnreachableDiscoveredWebsites': value.showUnreachableDiscoveredWebsites,
    };
}
//# sourceMappingURL=AwsConnectionInfoModel.js.map