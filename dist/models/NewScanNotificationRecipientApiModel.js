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
 * @export
 */
export const NewScanNotificationRecipientApiModelSpecificEmailRecipientsEnum = {
    None: 'None',
    WebsiteTechnicalContact: 'WebsiteTechnicalContact',
    PersonWhoStartedScan: 'PersonWhoStartedScan',
    AllAuthorized: 'AllAuthorized',
    AccountAdmins: 'AccountAdmins'
};
/**
 * @export
 */
export const NewScanNotificationRecipientApiModelSpecificSmsRecipientsEnum = {
    None: 'None',
    WebsiteTechnicalContact: 'WebsiteTechnicalContact',
    PersonWhoStartedScan: 'PersonWhoStartedScan',
    AllAuthorized: 'AllAuthorized',
    AccountAdmins: 'AccountAdmins'
};
/**
 * Check if a given object implements the NewScanNotificationRecipientApiModel interface.
 */
export function instanceOfNewScanNotificationRecipientApiModel(value) {
    let isInstance = true;
    return isInstance;
}
export function NewScanNotificationRecipientApiModelFromJSON(json) {
    return NewScanNotificationRecipientApiModelFromJSONTyped(json, false);
}
export function NewScanNotificationRecipientApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'emails': !exists(json, 'Emails') ? undefined : json['Emails'],
        'excludedUsers': !exists(json, 'ExcludedUsers') ? undefined : json['ExcludedUsers'],
        'integrations': !exists(json, 'Integrations') ? undefined : json['Integrations'],
        'phoneNumbers': !exists(json, 'PhoneNumbers') ? undefined : json['PhoneNumbers'],
        'outsiderRecipients': !exists(json, 'OutsiderRecipients') ? undefined : json['OutsiderRecipients'],
        'specificEmailRecipients': !exists(json, 'SpecificEmailRecipients') ? undefined : json['SpecificEmailRecipients'],
        'specificSmsRecipients': !exists(json, 'SpecificSmsRecipients') ? undefined : json['SpecificSmsRecipients'],
    };
}
export function NewScanNotificationRecipientApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'Emails': value.emails,
        'ExcludedUsers': value.excludedUsers,
        'Integrations': value.integrations,
        'PhoneNumbers': value.phoneNumbers,
        'OutsiderRecipients': value.outsiderRecipients,
        'SpecificEmailRecipients': value.specificEmailRecipients,
        'SpecificSmsRecipients': value.specificSmsRecipients,
    };
}
//# sourceMappingURL=NewScanNotificationRecipientApiModel.js.map