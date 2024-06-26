"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.DiscoveryConnectionsViewModelToJSON = exports.DiscoveryConnectionsViewModelFromJSONTyped = exports.DiscoveryConnectionsViewModelFromJSON = exports.instanceOfDiscoveryConnectionsViewModel = exports.DiscoveryConnectionsViewModelTypeEnum = void 0;
const AwsConnectionInfoModel_1 = require("./AwsConnectionInfoModel");
/**
 * @export
 */
exports.DiscoveryConnectionsViewModelTypeEnum = {
    Aws: 'Aws'
};
/**
 * Check if a given object implements the DiscoveryConnectionsViewModel interface.
 */
function instanceOfDiscoveryConnectionsViewModel(value) {
    if (!('name' in value))
        return false;
    return true;
}
exports.instanceOfDiscoveryConnectionsViewModel = instanceOfDiscoveryConnectionsViewModel;
function DiscoveryConnectionsViewModelFromJSON(json) {
    return DiscoveryConnectionsViewModelFromJSONTyped(json, false);
}
exports.DiscoveryConnectionsViewModelFromJSON = DiscoveryConnectionsViewModelFromJSON;
function DiscoveryConnectionsViewModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'name': json['Name'],
        'type': json['Type'] == null ? undefined : json['Type'],
        'id': json['Id'] == null ? undefined : json['Id'],
        'awsConnectionInfo': json['AwsConnectionInfo'] == null ? undefined : (0, AwsConnectionInfoModel_1.AwsConnectionInfoModelFromJSON)(json['AwsConnectionInfo']),
    };
}
exports.DiscoveryConnectionsViewModelFromJSONTyped = DiscoveryConnectionsViewModelFromJSONTyped;
function DiscoveryConnectionsViewModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Name': value['name'],
        'Type': value['type'],
        'Id': value['id'],
        'AwsConnectionInfo': (0, AwsConnectionInfoModel_1.AwsConnectionInfoModelToJSON)(value['awsConnectionInfo']),
    };
}
exports.DiscoveryConnectionsViewModelToJSON = DiscoveryConnectionsViewModelToJSON;
//# sourceMappingURL=DiscoveryConnectionsViewModel.js.map