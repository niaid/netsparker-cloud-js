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

import { mapValues } from '../runtime';
import type { AccessTokenTableModel } from './AccessTokenTableModel';
import {
    AccessTokenTableModelFromJSON,
    AccessTokenTableModelFromJSONTyped,
    AccessTokenTableModelToJSON,
} from './AccessTokenTableModel';
import type { AuthorizationCodeTableModel } from './AuthorizationCodeTableModel';
import {
    AuthorizationCodeTableModelFromJSON,
    AuthorizationCodeTableModelFromJSONTyped,
    AuthorizationCodeTableModelToJSON,
} from './AuthorizationCodeTableModel';
import type { ResponseFields } from './ResponseFields';
import {
    ResponseFieldsFromJSON,
    ResponseFieldsFromJSONTyped,
    ResponseFieldsToJSON,
} from './ResponseFields';
import type { OAuth2SettingEndPointModel } from './OAuth2SettingEndPointModel';
import {
    OAuth2SettingEndPointModelFromJSON,
    OAuth2SettingEndPointModelFromJSONTyped,
    OAuth2SettingEndPointModelToJSON,
} from './OAuth2SettingEndPointModel';
import type { ThreeLeggedFields } from './ThreeLeggedFields';
import {
    ThreeLeggedFieldsFromJSON,
    ThreeLeggedFieldsFromJSONTyped,
    ThreeLeggedFieldsToJSON,
} from './ThreeLeggedFields';
import type { SelectOptionModel } from './SelectOptionModel';
import {
    SelectOptionModelFromJSON,
    SelectOptionModelFromJSONTyped,
    SelectOptionModelToJSON,
} from './SelectOptionModel';

/**
 * Represents oauth2 model.
 * @export
 * @interface OAuth2SettingModel
 */
export interface OAuth2SettingModel {
    /**
     * Gets or sets the selected SerializedPolicyData.
     * @type {string}
     * @memberof OAuth2SettingModel
     */
    serializedPolicyData?: string;
    /**
     * Gets or sets whether the oauth2 authentication is enabled;
     * @type {boolean}
     * @memberof OAuth2SettingModel
     */
    enabled?: boolean;
    /**
     * Gets or sets the selected Flow.
     * @type {string}
     * @memberof OAuth2SettingModel
     */
    selectedFlowType?: OAuth2SettingModelSelectedFlowTypeEnum;
    /**
     * Gets or sets the Selected Authentication Type.
     * @type {string}
     * @memberof OAuth2SettingModel
     */
    selectedAuthenticationType?: OAuth2SettingModelSelectedAuthenticationTypeEnum;
    /**
     * Gets or sets the FlowTypes as label/value pair.
     * @type {Array<SelectOptionModel>}
     * @memberof OAuth2SettingModel
     */
    flowTypes?: Array<SelectOptionModel>;
    /**
     * Gets or sets the Authentications as label/value pair.
     * @type {Array<SelectOptionModel>}
     * @memberof OAuth2SettingModel
     */
    authentications?: Array<SelectOptionModel>;
    /**
     * 
     * @type {OAuth2SettingEndPointModel}
     * @memberof OAuth2SettingModel
     */
    accessTokenEndpoint?: OAuth2SettingEndPointModel;
    /**
     * 
     * @type {OAuth2SettingEndPointModel}
     * @memberof OAuth2SettingModel
     */
    authorizationCodeEndpoint?: OAuth2SettingEndPointModel;
    /**
     * 
     * @type {AccessTokenTableModel}
     * @memberof OAuth2SettingModel
     */
    accessTokenTable?: AccessTokenTableModel;
    /**
     * 
     * @type {AuthorizationCodeTableModel}
     * @memberof OAuth2SettingModel
     */
    authorizationCodeTable?: AuthorizationCodeTableModel;
    /**
     * 
     * @type {ResponseFields}
     * @memberof OAuth2SettingModel
     */
    responseFieldForm?: ResponseFields;
    /**
     * 
     * @type {ThreeLeggedFields}
     * @memberof OAuth2SettingModel
     */
    threeLegged?: ThreeLeggedFields;
}


/**
 * @export
 */
export const OAuth2SettingModelSelectedFlowTypeEnum = {
    AuthorizationCode: 'AuthorizationCode',
    Implicit: 'Implicit',
    ResourceOwnerPasswordCredentials: 'ResourceOwnerPasswordCredentials',
    ClientCredentials: 'ClientCredentials',
    Custom: 'Custom'
} as const;
export type OAuth2SettingModelSelectedFlowTypeEnum = typeof OAuth2SettingModelSelectedFlowTypeEnum[keyof typeof OAuth2SettingModelSelectedFlowTypeEnum];

/**
 * @export
 */
export const OAuth2SettingModelSelectedAuthenticationTypeEnum = {
    None: 'None',
    Form: 'Form',
    Basic: 'Basic'
} as const;
export type OAuth2SettingModelSelectedAuthenticationTypeEnum = typeof OAuth2SettingModelSelectedAuthenticationTypeEnum[keyof typeof OAuth2SettingModelSelectedAuthenticationTypeEnum];


/**
 * Check if a given object implements the OAuth2SettingModel interface.
 */
export function instanceOfOAuth2SettingModel(value: object): boolean {
    return true;
}

export function OAuth2SettingModelFromJSON(json: any): OAuth2SettingModel {
    return OAuth2SettingModelFromJSONTyped(json, false);
}

export function OAuth2SettingModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): OAuth2SettingModel {
    if (json == null) {
        return json;
    }
    return {
        
        'serializedPolicyData': json['SerializedPolicyData'] == null ? undefined : json['SerializedPolicyData'],
        'enabled': json['Enabled'] == null ? undefined : json['Enabled'],
        'selectedFlowType': json['SelectedFlowType'] == null ? undefined : json['SelectedFlowType'],
        'selectedAuthenticationType': json['SelectedAuthenticationType'] == null ? undefined : json['SelectedAuthenticationType'],
        'flowTypes': json['FlowTypes'] == null ? undefined : ((json['FlowTypes'] as Array<any>).map(SelectOptionModelFromJSON)),
        'authentications': json['Authentications'] == null ? undefined : ((json['Authentications'] as Array<any>).map(SelectOptionModelFromJSON)),
        'accessTokenEndpoint': json['AccessTokenEndpoint'] == null ? undefined : OAuth2SettingEndPointModelFromJSON(json['AccessTokenEndpoint']),
        'authorizationCodeEndpoint': json['AuthorizationCodeEndpoint'] == null ? undefined : OAuth2SettingEndPointModelFromJSON(json['AuthorizationCodeEndpoint']),
        'accessTokenTable': json['AccessTokenTable'] == null ? undefined : AccessTokenTableModelFromJSON(json['AccessTokenTable']),
        'authorizationCodeTable': json['AuthorizationCodeTable'] == null ? undefined : AuthorizationCodeTableModelFromJSON(json['AuthorizationCodeTable']),
        'responseFieldForm': json['ResponseFieldForm'] == null ? undefined : ResponseFieldsFromJSON(json['ResponseFieldForm']),
        'threeLegged': json['ThreeLegged'] == null ? undefined : ThreeLeggedFieldsFromJSON(json['ThreeLegged']),
    };
}

export function OAuth2SettingModelToJSON(value?: OAuth2SettingModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'SerializedPolicyData': value['serializedPolicyData'],
        'Enabled': value['enabled'],
        'SelectedFlowType': value['selectedFlowType'],
        'SelectedAuthenticationType': value['selectedAuthenticationType'],
        'FlowTypes': value['flowTypes'] == null ? undefined : ((value['flowTypes'] as Array<any>).map(SelectOptionModelToJSON)),
        'Authentications': value['authentications'] == null ? undefined : ((value['authentications'] as Array<any>).map(SelectOptionModelToJSON)),
        'AccessTokenEndpoint': OAuth2SettingEndPointModelToJSON(value['accessTokenEndpoint']),
        'AuthorizationCodeEndpoint': OAuth2SettingEndPointModelToJSON(value['authorizationCodeEndpoint']),
        'AccessTokenTable': AccessTokenTableModelToJSON(value['accessTokenTable']),
        'AuthorizationCodeTable': AuthorizationCodeTableModelToJSON(value['authorizationCodeTable']),
        'ResponseFieldForm': ResponseFieldsToJSON(value['responseFieldForm']),
        'ThreeLegged': ThreeLeggedFieldsToJSON(value['threeLegged']),
    };
}

