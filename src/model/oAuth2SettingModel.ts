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
import { AccessTokenTableModel } from './accessTokenTableModel';
import { AuthorizationCodeTableModel } from './authorizationCodeTableModel';
import { OAuth2SettingEndPointModel } from './oAuth2SettingEndPointModel';
import { ResponseFields } from './responseFields';
import { SelectOptionModel } from './selectOptionModel';
import { ThreeLeggedFields } from './threeLeggedFields';

/**
* Represents oauth2 model.
*/
export class OAuth2SettingModel {
    /**
    * Gets or sets the selected SerializedPolicyData.
    */
    'serializedPolicyData'?: string;
    /**
    * Gets or sets whether the oauth2 authentication is enabled;
    */
    'enabled'?: boolean;
    /**
    * Gets or sets the selected Flow.
    */
    'selectedFlowType'?: OAuth2SettingModel.SelectedFlowTypeEnum;
    /**
    * Gets or sets the Selected Authentication Type.
    */
    'selectedAuthenticationType'?: OAuth2SettingModel.SelectedAuthenticationTypeEnum;
    /**
    * Gets or sets the FlowTypes as label/value pair.
    */
    'flowTypes'?: Array<SelectOptionModel>;
    /**
    * Gets or sets the Authentications as label/value pair.
    */
    'authentications'?: Array<SelectOptionModel>;
    'accessTokenEndpoint'?: OAuth2SettingEndPointModel;
    'authorizationCodeEndpoint'?: OAuth2SettingEndPointModel;
    'accessTokenTable'?: AccessTokenTableModel;
    'authorizationCodeTable'?: AuthorizationCodeTableModel;
    'responseFieldForm'?: ResponseFields;
    'threeLegged'?: ThreeLeggedFields;

    static discriminator: string | undefined = undefined;

    static attributeTypeMap: Array<{name: string, baseName: string, type: string}> = [
        {
            "name": "serializedPolicyData",
            "baseName": "SerializedPolicyData",
            "type": "string"
        },
        {
            "name": "enabled",
            "baseName": "Enabled",
            "type": "boolean"
        },
        {
            "name": "selectedFlowType",
            "baseName": "SelectedFlowType",
            "type": "OAuth2SettingModel.SelectedFlowTypeEnum"
        },
        {
            "name": "selectedAuthenticationType",
            "baseName": "SelectedAuthenticationType",
            "type": "OAuth2SettingModel.SelectedAuthenticationTypeEnum"
        },
        {
            "name": "flowTypes",
            "baseName": "FlowTypes",
            "type": "Array<SelectOptionModel>"
        },
        {
            "name": "authentications",
            "baseName": "Authentications",
            "type": "Array<SelectOptionModel>"
        },
        {
            "name": "accessTokenEndpoint",
            "baseName": "AccessTokenEndpoint",
            "type": "OAuth2SettingEndPointModel"
        },
        {
            "name": "authorizationCodeEndpoint",
            "baseName": "AuthorizationCodeEndpoint",
            "type": "OAuth2SettingEndPointModel"
        },
        {
            "name": "accessTokenTable",
            "baseName": "AccessTokenTable",
            "type": "AccessTokenTableModel"
        },
        {
            "name": "authorizationCodeTable",
            "baseName": "AuthorizationCodeTable",
            "type": "AuthorizationCodeTableModel"
        },
        {
            "name": "responseFieldForm",
            "baseName": "ResponseFieldForm",
            "type": "ResponseFields"
        },
        {
            "name": "threeLegged",
            "baseName": "ThreeLegged",
            "type": "ThreeLeggedFields"
        }    ];

    static getAttributeTypeMap() {
        return OAuth2SettingModel.attributeTypeMap;
    }
}

export namespace OAuth2SettingModel {
    export enum SelectedFlowTypeEnum {
        AuthorizationCode = <any> 'AuthorizationCode',
        Implicit = <any> 'Implicit',
        ResourceOwnerPasswordCredentials = <any> 'ResourceOwnerPasswordCredentials',
        ClientCredentials = <any> 'ClientCredentials',
        Custom = <any> 'Custom'
    }
    export enum SelectedAuthenticationTypeEnum {
        None = <any> 'None',
        Form = <any> 'Form',
        Basic = <any> 'Basic'
    }
}
