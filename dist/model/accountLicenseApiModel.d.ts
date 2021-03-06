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
import { LicenseBaseModel } from './licenseBaseModel';
/**
* Provides information about user\'s account license.
*/
export declare class AccountLicenseApiModel {
    /**
    * Gets or sets the maximum number of subscription websites that user can have.
    */
    'subscriptionMaximumSiteLimit'?: number;
    /**
    * Gets or sets the added site count.
    */
    'subscriptionSiteCount'?: number;
    /**
    * Gets or sets the this subscription\'s end date.
    */
    'subscriptionEndDate'?: string;
    /**
    * Gets or sets the this subscription\'s start date.
    */
    'subscriptionStartDate'?: string;
    /**
    * Gets or sets a value indicating whether this account is whitelisted.
    */
    'isAccountWhitelisted'?: boolean;
    /**
    * Gets or sets the how many scan credits has been used on related account.
    */
    'usedScanCreditCount'?: number;
    /**
    * Gets or sets the available scan credit count of account license.
    */
    'scanCreditCount'?: number;
    /**
    * Gets or sets a value indicating whether credit scan is enabled.
    */
    'isCreditScanEnabled'?: boolean;
    /**
    * Gets or sets a value indicating whether subscription is enabled.
    */
    'isSubscriptionEnabled'?: boolean;
    /**
    * Gets or sets the pre-verified websites.
    */
    'preVerifiedWebsites'?: Array<string>;
    /**
    * Gets or sets the licenses.
    */
    'licenses'?: Array<LicenseBaseModel>;
    static discriminator: string | undefined;
    static attributeTypeMap: Array<{
        name: string;
        baseName: string;
        type: string;
    }>;
    static getAttributeTypeMap(): {
        name: string;
        baseName: string;
        type: string;
    }[];
}
