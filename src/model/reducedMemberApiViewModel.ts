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

import { RequestFile } from './models';

export class ReducedMemberApiViewModel {
    /**
    * Gets or sets the foreign key reference to the related User instance.
    */
    'id'?: string;
    /**
    * Gets or sets the account identifier.
    */
    'accountId'?: string;
    /**
    * Gets or sets the display name of the user.
    */
    'name'?: string;
    /**
    * Gets or sets the email.
    */
    'email'?: string;
    /**
    * Gets or sets the alternative login email.
    */
    'alternateLoginEmail'?: string;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "id",
            "baseName": "Id",
            "type": "string"
        },
        {
            "name": "accountId",
            "baseName": "AccountId",
            "type": "string"
        },
        {
            "name": "name",
            "baseName": "Name",
            "type": "string"
        },
        {
            "name": "email",
            "baseName": "Email",
            "type": "string"
        },
        {
            "name": "alternateLoginEmail",
            "baseName": "AlternateLoginEmail",
            "type": "string"
        }    ];

    static getAttributeTypeMap() {
        return ReducedMemberApiViewModel.attributeTypeMap;
    }
}

