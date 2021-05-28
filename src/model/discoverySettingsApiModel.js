"use strict";
/**
 * Netsparker Enterprise API
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
/**
* Discovery Settings api model.
*/
class DiscoverySettingsApiModel {
    static getAttributeTypeMap() {
        return DiscoverySettingsApiModel.attributeTypeMap;
    }
}
DiscoverySettingsApiModel.discriminator = undefined;
DiscoverySettingsApiModel.attributeTypeMap = [
    {
        "name": "includedSlds",
        "baseName": "IncludedSlds",
        "type": "string"
    },
    {
        "name": "includedIpRanges",
        "baseName": "IncludedIpRanges",
        "type": "string"
    },
    {
        "name": "includedOrganizations",
        "baseName": "IncludedOrganizations",
        "type": "string"
    },
    {
        "name": "excludedSlds",
        "baseName": "ExcludedSlds",
        "type": "string"
    },
    {
        "name": "excludedTlds",
        "baseName": "ExcludedTlds",
        "type": "string"
    },
    {
        "name": "excludedIpAddresses",
        "baseName": "ExcludedIpAddresses",
        "type": "string"
    },
    {
        "name": "excludedOrganizations",
        "baseName": "ExcludedOrganizations",
        "type": "string"
    },
    {
        "name": "onlyRegisteredDomains",
        "baseName": "OnlyRegisteredDomains",
        "type": "boolean"
    },
    {
        "name": "sharedHostMatching",
        "baseName": "SharedHostMatching",
        "type": "boolean"
    },
    {
        "name": "organizationNameMatching",
        "baseName": "OrganizationNameMatching",
        "type": "boolean"
    },
    {
        "name": "emailMatching",
        "baseName": "EmailMatching",
        "type": "boolean"
    },
    {
        "name": "websitesMatching",
        "baseName": "WebsitesMatching",
        "type": "boolean"
    }
];
exports.DiscoverySettingsApiModel = DiscoverySettingsApiModel;
//# sourceMappingURL=discoverySettingsApiModel.js.map