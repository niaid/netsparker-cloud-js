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
import { OutsiderRecipient } from './outsiderRecipient';
import { ScanNotificationRecipientUserApiModel } from './scanNotificationRecipientUserApiModel';
/**
* Represents a model for carrying out a scan notification recipient data
*/
export declare class ScanNotificationRecipientApiModel {
    /**
    * Gets or sets the users who will be notified via OutsiderRecipients.
    */
    'outsiderRecipients'?: Array<OutsiderRecipient>;
    /**
    * Gets or sets the users who will be notified via Email.
    */
    'emailRecipientUsers'?: Array<ScanNotificationRecipientUserApiModel>;
    /**
    * Gets or sets the users who won\'t be notified
    */
    'excludedUsers'?: Array<ScanNotificationRecipientUserApiModel>;
    /**
    * Gets or sets the integration end points which will be notified.
    */
    'integrationRecipients'?: Array<string>;
    /**
    * Gets or sets the users who will be notified via SMS.
    */
    'smsRecipientUsers'?: Array<ScanNotificationRecipientUserApiModel>;
    /**
    * Gets or sets the specific recipients who will be notified via Email.
    */
    'specificEmailRecipients'?: Array<ScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum>;
    /**
    * Gets or sets the specific recipients who will be notified via SMS.
    */
    'specificSmsRecipients'?: Array<ScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum>;
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
export declare namespace ScanNotificationRecipientApiModel {
    enum SpecificEmailRecipientsEnum {
        None,
        WebsiteTechnicalContact,
        PersonWhoStartedScan,
        AllAuthorized,
        AccountAdmins
    }
    enum SpecificSmsRecipientsEnum {
        None,
        WebsiteTechnicalContact,
        PersonWhoStartedScan,
        AllAuthorized,
        AccountAdmins
    }
}