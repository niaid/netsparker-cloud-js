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
import type { BasicAuthenticationSettingApiModel } from './BasicAuthenticationSettingApiModel';
import type { FormAuthenticationSettingApiModel } from './FormAuthenticationSettingApiModel';
import type { NameValuePair } from './NameValuePair';
import type { OAuth2SettingEndpoint } from './OAuth2SettingEndpoint';
import type { ResponseFields } from './ResponseFields';
import type { ThreeLeggedFields } from './ThreeLeggedFields';
/**
 * Provides an inputs for OAuth 2.0 Flow.
 * @export
 * @interface OAuth2SettingApiModel
 */
export interface OAuth2SettingApiModel {
    /**
     * Gets or sets the SerializedPolicyData.
     * @type {string}
     * @memberof OAuth2SettingApiModel
     */
    serializedPolicyData?: string;
    /**
     *
     * @type {string}
     * @memberof OAuth2SettingApiModel
     */
    flowType?: OAuth2SettingApiModelFlowTypeEnum;
    /**
     *
     * @type {string}
     * @memberof OAuth2SettingApiModel
     */
    authenticationType?: OAuth2SettingApiModelAuthenticationTypeEnum;
    /**
     *
     * @type {OAuth2SettingEndpoint}
     * @memberof OAuth2SettingApiModel
     */
    accessTokenEndpoint?: OAuth2SettingEndpoint;
    /**
     *
     * @type {OAuth2SettingEndpoint}
     * @memberof OAuth2SettingApiModel
     */
    authorizationCodeEndpoint?: OAuth2SettingEndpoint;
    /**
     *
     * @type {Array<NameValuePair>}
     * @memberof OAuth2SettingApiModel
     */
    accessTokenItems?: Array<NameValuePair>;
    /**
     *
     * @type {Array<NameValuePair>}
     * @memberof OAuth2SettingApiModel
     */
    authorizationCodeItems?: Array<NameValuePair>;
    /**
     *
     * @type {ResponseFields}
     * @memberof OAuth2SettingApiModel
     */
    responseFields?: ResponseFields;
    /**
     *
     * @type {ThreeLeggedFields}
     * @memberof OAuth2SettingApiModel
     */
    threeLeggedFields?: ThreeLeggedFields;
    /**
     * Gets or sets the identifier.
     * @type {string}
     * @memberof OAuth2SettingApiModel
     */
    id?: string;
    /**
     * Gets or sets whether oauth2 is enabled.
     * @type {boolean}
     * @memberof OAuth2SettingApiModel
     */
    enabled?: boolean;
    /**
     * Gets or sets the header authentication settings.
     * @type {Array<NameValuePair>}
     * @memberof OAuth2SettingApiModel
     */
    headers?: Array<NameValuePair>;
    /**
     *
     * @type {FormAuthenticationSettingApiModel}
     * @memberof OAuth2SettingApiModel
     */
    formAuthenticationSetting?: FormAuthenticationSettingApiModel;
    /**
     *
     * @type {BasicAuthenticationSettingApiModel}
     * @memberof OAuth2SettingApiModel
     */
    basicAuthenticationSetting?: BasicAuthenticationSettingApiModel;
}
/**
 * @export
 */
export declare const OAuth2SettingApiModelFlowTypeEnum: {
    readonly AuthorizationCode: "AuthorizationCode";
    readonly Implicit: "Implicit";
    readonly ResourceOwnerPasswordCredentials: "ResourceOwnerPasswordCredentials";
    readonly ClientCredentials: "ClientCredentials";
    readonly Custom: "Custom";
};
export type OAuth2SettingApiModelFlowTypeEnum = typeof OAuth2SettingApiModelFlowTypeEnum[keyof typeof OAuth2SettingApiModelFlowTypeEnum];
/**
 * @export
 */
export declare const OAuth2SettingApiModelAuthenticationTypeEnum: {
    readonly None: "None";
    readonly Form: "Form";
    readonly Basic: "Basic";
};
export type OAuth2SettingApiModelAuthenticationTypeEnum = typeof OAuth2SettingApiModelAuthenticationTypeEnum[keyof typeof OAuth2SettingApiModelAuthenticationTypeEnum];
/**
 * Check if a given object implements the OAuth2SettingApiModel interface.
 */
export declare function instanceOfOAuth2SettingApiModel(value: object): boolean;
export declare function OAuth2SettingApiModelFromJSON(json: any): OAuth2SettingApiModel;
export declare function OAuth2SettingApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): OAuth2SettingApiModel;
export declare function OAuth2SettingApiModelToJSON(value?: OAuth2SettingApiModel | null): any;
