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
/**
 * Defines a type for outsider recipient needs.
 * @export
 * @interface OutsiderRecipient
 */
export interface OutsiderRecipient {
    /**
     * Gets or sets the email.
     * @type {string}
     * @memberof OutsiderRecipient
     */
    email?: string;
}
/**
 * Check if a given object implements the OutsiderRecipient interface.
 */
export declare function instanceOfOutsiderRecipient(value: object): boolean;
export declare function OutsiderRecipientFromJSON(json: any): OutsiderRecipient;
export declare function OutsiderRecipientFromJSONTyped(json: any, ignoreDiscriminator: boolean): OutsiderRecipient;
export declare function OutsiderRecipientToJSON(value?: OutsiderRecipient | null): any;
