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
import type { ReducedTeamDto } from './ReducedTeamDto';
import type { RoleWebsiteGroupMappingDto } from './RoleWebsiteGroupMappingDto';
/**
 *
 * @export
 * @interface MemberApiViewModel
 */
export interface MemberApiViewModel {
    /**
     * Gets or sets the foreign key reference to the related User instance.
     * @type {string}
     * @memberof MemberApiViewModel
     */
    id?: string;
    /**
     * Gets or sets the account identifier.
     * @type {string}
     * @memberof MemberApiViewModel
     */
    accountId?: string;
    /**
     * Gets or sets the display name of the user.
     * @type {string}
     * @memberof MemberApiViewModel
     */
    name?: string;
    /**
     * Gets or sets the email.
     * @type {string}
     * @memberof MemberApiViewModel
     */
    email?: string;
    /**
     * Gets or sets a value indicating whether api access is enabled for user.
     * @type {boolean}
     * @memberof MemberApiViewModel
     */
    isApiAccessEnabled?: boolean;
    /**
     * Gets or sets the phone number.
     * @type {string}
     * @memberof MemberApiViewModel
     */
    phoneNumber?: string;
    /**
     * Gets or sets user date format that defines the culturally appropriate format of displaying dates and times.
     * You can use these values ; dd/MM/yyyy and MM/dd/yyyy. Default : dd/MM/yyyy.
     * @type {string}
     * @memberof MemberApiViewModel
     */
    dateTimeFormat?: string;
    /**
     * Gets or sets the user's time zone.
     * You can check out following endpoint to see all of time zones. Api endpoint : /api/1.0/teams/gettimezones. Default :
     * GMT Standard Time.
     * @type {string}
     * @memberof MemberApiViewModel
     */
    timezoneId?: string;
    /**
     * Gets or sets the state of the user.
     * @type {string}
     * @memberof MemberApiViewModel
     */
    state?: MemberApiViewModelStateEnum;
    /**
     * Gets or sets the allowed site limit.
     * @type {number}
     * @memberof MemberApiViewModel
     */
    allowedWebsiteLimit?: number;
    /**
     * Gets or sets a value indicating whether two factor authentication is enabled for this user.
     * @type {boolean}
     * @memberof MemberApiViewModel
     */
    isTwoFactorAuthenticationEnabled?: boolean;
    /**
     * Gets or sets the alternative login email.
     * @type {string}
     * @memberof MemberApiViewModel
     */
    alternateLoginEmail?: string;
    /**
     * User direct roles
     * @type {Array<RoleWebsiteGroupMappingDto>}
     * @memberof MemberApiViewModel
     */
    roleWebsiteGroupMappings?: Array<RoleWebsiteGroupMappingDto>;
    /**
     * User Teams
     * @type {Array<ReducedTeamDto>}
     * @memberof MemberApiViewModel
     */
    teams?: Array<ReducedTeamDto>;
    /**
     * Gets or sets a value indicating whether this user is enforced for SSO.
     * @type {boolean}
     * @memberof MemberApiViewModel
     */
    onlySsoLogin?: boolean;
    /**
     * Gets or sets the date which this entity was created at.
     * @type {Date}
     * @memberof MemberApiViewModel
     */
    createdAt?: Date;
    /**
     * Gets or sets the modification timestamp which is used for concurrency checking.
     * @type {Date}
     * @memberof MemberApiViewModel
     */
    lastLoginDate?: Date;
    /**
     *
     * @type {number}
     * @memberof MemberApiViewModel
     */
    websiteCount?: number;
}
/**
* @export
* @enum {string}
*/
export declare enum MemberApiViewModelStateEnum {
    Enabled = "Enabled",
    Disabled = "Disabled"
}
/**
 * Check if a given object implements the MemberApiViewModel interface.
 */
export declare function instanceOfMemberApiViewModel(value: object): boolean;
export declare function MemberApiViewModelFromJSON(json: any): MemberApiViewModel;
export declare function MemberApiViewModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): MemberApiViewModel;
export declare function MemberApiViewModelToJSON(value?: MemberApiViewModel | null): any;
