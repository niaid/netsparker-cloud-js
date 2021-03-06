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

import { RequestFile } from './models';
import { ReducedTeamApiViewModel } from './reducedTeamApiViewModel';
import { RoleWebsiteGroupMappingApiViewModel } from './roleWebsiteGroupMappingApiViewModel';

export class MemberInvitationApiViewModel {
    /**
    * Gets or sets the identifier.
    */
    'id'?: string;
    /**
    * Gets or sets the invitation\'s account identifier.
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
    * Gets or sets a value indicating where api access is enabled for user.
    */
    'isApiAccessEnabled'?: boolean;
    /**
    * Gets or sets the phone number.
    */
    'phoneNumber'?: string;
    /**
    * Gets or sets a value indicating whether the allowed site limit that user can create.
    */
    'allowedWebsiteLimit'?: number;
    /**
    * Gets or sets the alternative login email.
    */
    'alternateLoginEmail'?: string;
    /**
    * With invitation, it checks whether the user has been created.
    */
    'inUse'?: boolean;
    /**
    * Selected users
    */
    'teams'?: Array<ReducedTeamApiViewModel>;
    /**
    * Selected Role Website Groups Mappings
    */
    'roleWebsiteGroupMappings'?: Array<RoleWebsiteGroupMappingApiViewModel>;
    /**
    * Is Alternate Login Email
    */
    'isAlternateLoginEmail'?: boolean;
    /**
    * Gets or sets a value indicating whether this user is enforced for SSO.
    */
    'onlySsoLogin'?: boolean;

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
            "name": "isApiAccessEnabled",
            "baseName": "IsApiAccessEnabled",
            "type": "boolean"
        },
        {
            "name": "phoneNumber",
            "baseName": "PhoneNumber",
            "type": "string"
        },
        {
            "name": "allowedWebsiteLimit",
            "baseName": "AllowedWebsiteLimit",
            "type": "number"
        },
        {
            "name": "alternateLoginEmail",
            "baseName": "AlternateLoginEmail",
            "type": "string"
        },
        {
            "name": "inUse",
            "baseName": "InUse",
            "type": "boolean"
        },
        {
            "name": "teams",
            "baseName": "Teams",
            "type": "Array<ReducedTeamApiViewModel>"
        },
        {
            "name": "roleWebsiteGroupMappings",
            "baseName": "RoleWebsiteGroupMappings",
            "type": "Array<RoleWebsiteGroupMappingApiViewModel>"
        },
        {
            "name": "isAlternateLoginEmail",
            "baseName": "IsAlternateLoginEmail",
            "type": "boolean"
        },
        {
            "name": "onlySsoLogin",
            "baseName": "OnlySsoLogin",
            "type": "boolean"
        }    ];

    static getAttributeTypeMap() {
        return MemberInvitationApiViewModel.attributeTypeMap;
    }
}

