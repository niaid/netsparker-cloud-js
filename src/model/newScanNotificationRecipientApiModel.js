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
exports.NewScanNotificationRecipientApiModel = void 0;
/**
* Represents a model for carrying out a new scan notification recipient data
*/
class NewScanNotificationRecipientApiModel {
    static getAttributeTypeMap() {
        return NewScanNotificationRecipientApiModel.attributeTypeMap;
    }
}
exports.NewScanNotificationRecipientApiModel = NewScanNotificationRecipientApiModel;
NewScanNotificationRecipientApiModel.discriminator = undefined;
NewScanNotificationRecipientApiModel.attributeTypeMap = [
    {
        "name": "emails",
        "baseName": "Emails",
        "type": "Array<string>"
    },
    {
        "name": "excludedUsers",
        "baseName": "ExcludedUsers",
        "type": "Array<string>"
    },
    {
        "name": "integrations",
        "baseName": "Integrations",
        "type": "Array<string>"
    },
    {
        "name": "phoneNumbers",
        "baseName": "PhoneNumbers",
        "type": "Array<string>"
    },
    {
        "name": "outsiderRecipients",
        "baseName": "OutsiderRecipients",
        "type": "Array<string>"
    },
    {
        "name": "specificEmailRecipients",
        "baseName": "SpecificEmailRecipients",
        "type": "Array<NewScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum>"
    },
    {
        "name": "specificSmsRecipients",
        "baseName": "SpecificSmsRecipients",
        "type": "Array<NewScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum>"
    }
];
(function (NewScanNotificationRecipientApiModel) {
    let SpecificEmailRecipientsEnum;
    (function (SpecificEmailRecipientsEnum) {
        SpecificEmailRecipientsEnum[SpecificEmailRecipientsEnum["None"] = 'None'] = "None";
        SpecificEmailRecipientsEnum[SpecificEmailRecipientsEnum["WebsiteTechnicalContact"] = 'WebsiteTechnicalContact'] = "WebsiteTechnicalContact";
        SpecificEmailRecipientsEnum[SpecificEmailRecipientsEnum["PersonWhoStartedScan"] = 'PersonWhoStartedScan'] = "PersonWhoStartedScan";
        SpecificEmailRecipientsEnum[SpecificEmailRecipientsEnum["AllAuthorized"] = 'AllAuthorized'] = "AllAuthorized";
        SpecificEmailRecipientsEnum[SpecificEmailRecipientsEnum["AccountAdmins"] = 'AccountAdmins'] = "AccountAdmins";
    })(SpecificEmailRecipientsEnum = NewScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum || (NewScanNotificationRecipientApiModel.SpecificEmailRecipientsEnum = {}));
    let SpecificSmsRecipientsEnum;
    (function (SpecificSmsRecipientsEnum) {
        SpecificSmsRecipientsEnum[SpecificSmsRecipientsEnum["None"] = 'None'] = "None";
        SpecificSmsRecipientsEnum[SpecificSmsRecipientsEnum["WebsiteTechnicalContact"] = 'WebsiteTechnicalContact'] = "WebsiteTechnicalContact";
        SpecificSmsRecipientsEnum[SpecificSmsRecipientsEnum["PersonWhoStartedScan"] = 'PersonWhoStartedScan'] = "PersonWhoStartedScan";
        SpecificSmsRecipientsEnum[SpecificSmsRecipientsEnum["AllAuthorized"] = 'AllAuthorized'] = "AllAuthorized";
        SpecificSmsRecipientsEnum[SpecificSmsRecipientsEnum["AccountAdmins"] = 'AccountAdmins'] = "AccountAdmins";
    })(SpecificSmsRecipientsEnum = NewScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum || (NewScanNotificationRecipientApiModel.SpecificSmsRecipientsEnum = {}));
})(NewScanNotificationRecipientApiModel = exports.NewScanNotificationRecipientApiModel || (exports.NewScanNotificationRecipientApiModel = {}));
//# sourceMappingURL=newScanNotificationRecipientApiModel.js.map