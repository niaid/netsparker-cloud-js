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

import { exists, mapValues } from '../runtime';
import type { BasicAuthenticationSettingApiModel } from './BasicAuthenticationSettingApiModel';
import {
    BasicAuthenticationSettingApiModelFromJSON,
    BasicAuthenticationSettingApiModelFromJSONTyped,
    BasicAuthenticationSettingApiModelToJSON,
} from './BasicAuthenticationSettingApiModel';
import type { FormAuthenticationSettingApiModel } from './FormAuthenticationSettingApiModel';
import {
    FormAuthenticationSettingApiModelFromJSON,
    FormAuthenticationSettingApiModelFromJSONTyped,
    FormAuthenticationSettingApiModelToJSON,
} from './FormAuthenticationSettingApiModel';
import type { NameValuePair } from './NameValuePair';
import {
    NameValuePairFromJSON,
    NameValuePairFromJSONTyped,
    NameValuePairToJSON,
} from './NameValuePair';
import type { OAuth2SettingEndpoint } from './OAuth2SettingEndpoint';
import {
    OAuth2SettingEndpointFromJSON,
    OAuth2SettingEndpointFromJSONTyped,
    OAuth2SettingEndpointToJSON,
} from './OAuth2SettingEndpoint';
import type { ResponseFields } from './ResponseFields';
import {
    ResponseFieldsFromJSON,
    ResponseFieldsFromJSONTyped,
    ResponseFieldsToJSON,
} from './ResponseFields';
import type { ThreeLeggedFields } from './ThreeLeggedFields';
import {
    ThreeLeggedFieldsFromJSON,
    ThreeLeggedFieldsFromJSONTyped,
    ThreeLeggedFieldsToJSON,
} from './ThreeLeggedFields';

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
export const OAuth2SettingApiModelFlowTypeEnum = {
    AuthorizationCode: 'AuthorizationCode',
    Implicit: 'Implicit',
    ResourceOwnerPasswordCredentials: 'ResourceOwnerPasswordCredentials',
    ClientCredentials: 'ClientCredentials',
    Custom: 'Custom'
} as const;
export type OAuth2SettingApiModelFlowTypeEnum = typeof OAuth2SettingApiModelFlowTypeEnum[keyof typeof OAuth2SettingApiModelFlowTypeEnum];

/**
 * @export
 */
export const OAuth2SettingApiModelAuthenticationTypeEnum = {
    None: 'None',
    Form: 'Form',
    Basic: 'Basic'
} as const;
export type OAuth2SettingApiModelAuthenticationTypeEnum = typeof OAuth2SettingApiModelAuthenticationTypeEnum[keyof typeof OAuth2SettingApiModelAuthenticationTypeEnum];


/**
 * Check if a given object implements the OAuth2SettingApiModel interface.
 */
export function instanceOfOAuth2SettingApiModel(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function OAuth2SettingApiModelFromJSON(json: any): OAuth2SettingApiModel {
    return OAuth2SettingApiModelFromJSONTyped(json, false);
}

export function OAuth2SettingApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): OAuth2SettingApiModel {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'serializedPolicyData': !exists(json, 'SerializedPolicyData') ? undefined : json['SerializedPolicyData'],
        'flowType': !exists(json, 'FlowType') ? undefined : json['FlowType'],
        'authenticationType': !exists(json, 'AuthenticationType') ? undefined : json['AuthenticationType'],
        'accessTokenEndpoint': !exists(json, 'AccessTokenEndpoint') ? undefined : OAuth2SettingEndpointFromJSON(json['AccessTokenEndpoint']),
        'authorizationCodeEndpoint': !exists(json, 'AuthorizationCodeEndpoint') ? undefined : OAuth2SettingEndpointFromJSON(json['AuthorizationCodeEndpoint']),
        'accessTokenItems': !exists(json, 'AccessTokenItems') ? undefined : ((json['AccessTokenItems'] as Array<any>).map(NameValuePairFromJSON)),
        'authorizationCodeItems': !exists(json, 'AuthorizationCodeItems') ? undefined : ((json['AuthorizationCodeItems'] as Array<any>).map(NameValuePairFromJSON)),
        'responseFields': !exists(json, 'ResponseFields') ? undefined : ResponseFieldsFromJSON(json['ResponseFields']),
        'threeLeggedFields': !exists(json, 'ThreeLeggedFields') ? undefined : ThreeLeggedFieldsFromJSON(json['ThreeLeggedFields']),
        'id': !exists(json, 'Id') ? undefined : json['Id'],
        'enabled': !exists(json, 'Enabled') ? undefined : json['Enabled'],
        'headers': !exists(json, 'Headers') ? undefined : ((json['Headers'] as Array<any>).map(NameValuePairFromJSON)),
        'formAuthenticationSetting': !exists(json, 'FormAuthenticationSetting') ? undefined : FormAuthenticationSettingApiModelFromJSON(json['FormAuthenticationSetting']),
        'basicAuthenticationSetting': !exists(json, 'BasicAuthenticationSetting') ? undefined : BasicAuthenticationSettingApiModelFromJSON(json['BasicAuthenticationSetting']),
    };
}

export function OAuth2SettingApiModelToJSON(value?: OAuth2SettingApiModel | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'SerializedPolicyData': value.serializedPolicyData,
        'FlowType': value.flowType,
        'AuthenticationType': value.authenticationType,
        'AccessTokenEndpoint': OAuth2SettingEndpointToJSON(value.accessTokenEndpoint),
        'AuthorizationCodeEndpoint': OAuth2SettingEndpointToJSON(value.authorizationCodeEndpoint),
        'AccessTokenItems': value.accessTokenItems === undefined ? undefined : ((value.accessTokenItems as Array<any>).map(NameValuePairToJSON)),
        'AuthorizationCodeItems': value.authorizationCodeItems === undefined ? undefined : ((value.authorizationCodeItems as Array<any>).map(NameValuePairToJSON)),
        'ResponseFields': ResponseFieldsToJSON(value.responseFields),
        'ThreeLeggedFields': ThreeLeggedFieldsToJSON(value.threeLeggedFields),
        'Id': value.id,
        'Enabled': value.enabled,
        'Headers': value.headers === undefined ? undefined : ((value.headers as Array<any>).map(NameValuePairToJSON)),
        'FormAuthenticationSetting': FormAuthenticationSettingApiModelToJSON(value.formAuthenticationSetting),
        'BasicAuthenticationSetting': BasicAuthenticationSettingApiModelToJSON(value.basicAuthenticationSetting),
    };
}
