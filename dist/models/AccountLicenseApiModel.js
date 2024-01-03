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
exports.AccountLicenseApiModelToJSON = exports.AccountLicenseApiModelFromJSONTyped = exports.AccountLicenseApiModelFromJSON = exports.instanceOfAccountLicenseApiModel = void 0;
const runtime_1 = require("../runtime");
const LicenseBaseModel_1 = require("./LicenseBaseModel");
/**
 * Check if a given object implements the AccountLicenseApiModel interface.
 */
function instanceOfAccountLicenseApiModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfAccountLicenseApiModel = instanceOfAccountLicenseApiModel;
function AccountLicenseApiModelFromJSON(json) {
    return AccountLicenseApiModelFromJSONTyped(json, false);
}
exports.AccountLicenseApiModelFromJSON = AccountLicenseApiModelFromJSON;
function AccountLicenseApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'subscriptionMaximumSiteLimit': !(0, runtime_1.exists)(json, 'SubscriptionMaximumSiteLimit') ? undefined : json['SubscriptionMaximumSiteLimit'],
        'subscriptionSiteCount': !(0, runtime_1.exists)(json, 'SubscriptionSiteCount') ? undefined : json['SubscriptionSiteCount'],
        'subscriptionEndDate': !(0, runtime_1.exists)(json, 'SubscriptionEndDate') ? undefined : json['SubscriptionEndDate'],
        'subscriptionStartDate': !(0, runtime_1.exists)(json, 'SubscriptionStartDate') ? undefined : json['SubscriptionStartDate'],
        'isAccountWhitelisted': !(0, runtime_1.exists)(json, 'IsAccountWhitelisted') ? undefined : json['IsAccountWhitelisted'],
        'usedScanCreditCount': !(0, runtime_1.exists)(json, 'UsedScanCreditCount') ? undefined : json['UsedScanCreditCount'],
        'scanCreditCount': !(0, runtime_1.exists)(json, 'ScanCreditCount') ? undefined : json['ScanCreditCount'],
        'isCreditScanEnabled': !(0, runtime_1.exists)(json, 'IsCreditScanEnabled') ? undefined : json['IsCreditScanEnabled'],
        'isSubscriptionEnabled': !(0, runtime_1.exists)(json, 'IsSubscriptionEnabled') ? undefined : json['IsSubscriptionEnabled'],
        'preVerifiedWebsites': !(0, runtime_1.exists)(json, 'PreVerifiedWebsites') ? undefined : json['PreVerifiedWebsites'],
        'licenses': !(0, runtime_1.exists)(json, 'Licenses') ? undefined : (json['Licenses'].map(LicenseBaseModel_1.LicenseBaseModelFromJSON)),
    };
}
exports.AccountLicenseApiModelFromJSONTyped = AccountLicenseApiModelFromJSONTyped;
function AccountLicenseApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'SubscriptionMaximumSiteLimit': value.subscriptionMaximumSiteLimit,
        'SubscriptionSiteCount': value.subscriptionSiteCount,
        'SubscriptionEndDate': value.subscriptionEndDate,
        'SubscriptionStartDate': value.subscriptionStartDate,
        'IsAccountWhitelisted': value.isAccountWhitelisted,
        'UsedScanCreditCount': value.usedScanCreditCount,
        'ScanCreditCount': value.scanCreditCount,
        'IsCreditScanEnabled': value.isCreditScanEnabled,
        'IsSubscriptionEnabled': value.isSubscriptionEnabled,
        'PreVerifiedWebsites': value.preVerifiedWebsites,
        'Licenses': value.licenses === undefined ? undefined : (value.licenses.map(LicenseBaseModel_1.LicenseBaseModelToJSON)),
    };
}
exports.AccountLicenseApiModelToJSON = AccountLicenseApiModelToJSON;
//# sourceMappingURL=AccountLicenseApiModel.js.map