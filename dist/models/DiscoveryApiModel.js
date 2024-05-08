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
exports.DiscoveryApiModelToJSON = exports.DiscoveryApiModelFromJSONTyped = exports.DiscoveryApiModelFromJSON = exports.instanceOfDiscoveryApiModel = exports.DiscoveryApiModelRiskScoreEnum = exports.DiscoveryApiModelDiscoverySourceTypeEnum = exports.DiscoveryApiModelStatusEnum = void 0;
const DiscoveryConnectionsApiModel_1 = require("./DiscoveryConnectionsApiModel");
/**
 * @export
 */
exports.DiscoveryApiModelStatusEnum = {
    Discovered: 'Discovered',
    Ignored: 'Ignored',
    Created: 'Created'
};
/**
 * @export
 */
exports.DiscoveryApiModelDiscoverySourceTypeEnum = {
    RadarDeepInfo: 'RadarDeepInfo',
    Aws: 'Aws'
};
/**
 * @export
 */
exports.DiscoveryApiModelRiskScoreEnum = {
    Low: 'Low',
    Medium: 'Medium',
    High: 'High',
    Critical: 'Critical',
    Loading: 'Loading',
    Undetermined: 'Undetermined',
    TemporaryUnavailable: 'TemporaryUnavailable'
};
/**
 * Check if a given object implements the DiscoveryApiModel interface.
 */
function instanceOfDiscoveryApiModel(value) {
    return true;
}
exports.instanceOfDiscoveryApiModel = instanceOfDiscoveryApiModel;
function DiscoveryApiModelFromJSON(json) {
    return DiscoveryApiModelFromJSONTyped(json, false);
}
exports.DiscoveryApiModelFromJSON = DiscoveryApiModelFromJSON;
function DiscoveryApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if (json == null) {
        return json;
    }
    return {
        'id': json['Id'] == null ? undefined : json['Id'],
        'subDomain': json['SubDomain'] == null ? undefined : json['SubDomain'],
        'secondLevelDomain': json['SecondLevelDomain'] == null ? undefined : json['SecondLevelDomain'],
        'secondLevelDomainCount': json['SecondLevelDomainCount'] == null ? undefined : json['SecondLevelDomainCount'],
        'topLevelDomain': json['TopLevelDomain'] == null ? undefined : json['TopLevelDomain'],
        'topLevelDomainCount': json['TopLevelDomainCount'] == null ? undefined : json['TopLevelDomainCount'],
        'authority': json['Authority'] == null ? undefined : json['Authority'],
        'https': json['Https'] == null ? undefined : json['Https'],
        'ipAddress': json['IpAddress'] == null ? undefined : json['IpAddress'],
        'ipAddressCount': json['IpAddressCount'] == null ? undefined : json['IpAddressCount'],
        'organizationName': json['OrganizationName'] == null ? undefined : json['OrganizationName'],
        'organizationNameCount': json['OrganizationNameCount'] == null ? undefined : json['OrganizationNameCount'],
        'copyright': json['Copyright'] == null ? undefined : json['Copyright'],
        'accountId': json['AccountId'] == null ? undefined : json['AccountId'],
        'websiteId': json['WebsiteId'] == null ? undefined : json['WebsiteId'],
        'websiteName': json['WebsiteName'] == null ? undefined : json['WebsiteName'],
        'distance': json['Distance'] == null ? undefined : json['Distance'],
        'status': json['Status'] == null ? undefined : json['Status'],
        'tags': json['Tags'] == null ? undefined : json['Tags'],
        'port': json['Port'] == null ? undefined : json['Port'],
        'discoverySourceType': json['DiscoverySourceType'] == null ? undefined : json['DiscoverySourceType'],
        'discoveryConnectionsDetail': json['DiscoveryConnectionsDetail'] == null ? undefined : (0, DiscoveryConnectionsApiModel_1.DiscoveryConnectionsApiModelFromJSON)(json['DiscoveryConnectionsDetail']),
        'riskScore': json['RiskScore'] == null ? undefined : json['RiskScore'],
    };
}
exports.DiscoveryApiModelFromJSONTyped = DiscoveryApiModelFromJSONTyped;
function DiscoveryApiModelToJSON(value) {
    if (value == null) {
        return value;
    }
    return {
        'Id': value['id'],
        'SubDomain': value['subDomain'],
        'SecondLevelDomain': value['secondLevelDomain'],
        'SecondLevelDomainCount': value['secondLevelDomainCount'],
        'TopLevelDomain': value['topLevelDomain'],
        'TopLevelDomainCount': value['topLevelDomainCount'],
        'Authority': value['authority'],
        'Https': value['https'],
        'IpAddress': value['ipAddress'],
        'OrganizationName': value['organizationName'],
        'OrganizationNameCount': value['organizationNameCount'],
        'Copyright': value['copyright'],
        'AccountId': value['accountId'],
        'WebsiteId': value['websiteId'],
        'WebsiteName': value['websiteName'],
        'Distance': value['distance'],
        'Status': value['status'],
        'Tags': value['tags'],
        'Port': value['port'],
        'DiscoverySourceType': value['discoverySourceType'],
        'DiscoveryConnectionsDetail': (0, DiscoveryConnectionsApiModel_1.DiscoveryConnectionsApiModelToJSON)(value['discoveryConnectionsDetail']),
        'RiskScore': value['riskScore'],
    };
}
exports.DiscoveryApiModelToJSON = DiscoveryApiModelToJSON;
//# sourceMappingURL=DiscoveryApiModel.js.map