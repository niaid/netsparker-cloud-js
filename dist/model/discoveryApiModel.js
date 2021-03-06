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
exports.DiscoveryApiModel = void 0;
class DiscoveryApiModel {
    static getAttributeTypeMap() {
        return DiscoveryApiModel.attributeTypeMap;
    }
}
exports.DiscoveryApiModel = DiscoveryApiModel;
DiscoveryApiModel.discriminator = undefined;
DiscoveryApiModel.attributeTypeMap = [
    {
        "name": "id",
        "baseName": "Id",
        "type": "string"
    },
    {
        "name": "subDomain",
        "baseName": "SubDomain",
        "type": "string"
    },
    {
        "name": "secondLevelDomain",
        "baseName": "SecondLevelDomain",
        "type": "string"
    },
    {
        "name": "secondLevelDomainCount",
        "baseName": "SecondLevelDomainCount",
        "type": "number"
    },
    {
        "name": "topLevelDomain",
        "baseName": "TopLevelDomain",
        "type": "string"
    },
    {
        "name": "topLevelDomainCount",
        "baseName": "TopLevelDomainCount",
        "type": "number"
    },
    {
        "name": "authority",
        "baseName": "Authority",
        "type": "string"
    },
    {
        "name": "https",
        "baseName": "Https",
        "type": "boolean"
    },
    {
        "name": "ipAddress",
        "baseName": "IpAddress",
        "type": "string"
    },
    {
        "name": "ipAddressCount",
        "baseName": "IpAddressCount",
        "type": "number"
    },
    {
        "name": "organizationName",
        "baseName": "OrganizationName",
        "type": "string"
    },
    {
        "name": "organizationNameCount",
        "baseName": "OrganizationNameCount",
        "type": "number"
    },
    {
        "name": "copyright",
        "baseName": "Copyright",
        "type": "string"
    },
    {
        "name": "accountId",
        "baseName": "AccountId",
        "type": "string"
    },
    {
        "name": "websiteId",
        "baseName": "WebsiteId",
        "type": "string"
    },
    {
        "name": "websiteName",
        "baseName": "WebsiteName",
        "type": "string"
    },
    {
        "name": "distance",
        "baseName": "Distance",
        "type": "number"
    },
    {
        "name": "status",
        "baseName": "Status",
        "type": "DiscoveryApiModel.StatusEnum"
    }
];
(function (DiscoveryApiModel) {
    let StatusEnum;
    (function (StatusEnum) {
        StatusEnum[StatusEnum["New"] = 'New'] = "New";
        StatusEnum[StatusEnum["Ignored"] = 'Ignored'] = "Ignored";
        StatusEnum[StatusEnum["Created"] = 'Created'] = "Created";
    })(StatusEnum = DiscoveryApiModel.StatusEnum || (DiscoveryApiModel.StatusEnum = {}));
})(DiscoveryApiModel = exports.DiscoveryApiModel || (exports.DiscoveryApiModel = {}));
//# sourceMappingURL=discoveryApiModel.js.map