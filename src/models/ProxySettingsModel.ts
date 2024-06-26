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
/**
 * Represents a model for carrying out authentication proxy settings.
 * @export
 * @interface ProxySettingsModel
 */
export interface ProxySettingsModel {
    /**
     * 
     * @type {Array<string>}
     * @memberof ProxySettingsModel
     */
    proxyByPassList?: Array<string>;
    /**
     * Gets or sets a value indicating whether custom proxy is enable .
     * @type {boolean}
     * @memberof ProxySettingsModel
     */
    enableCustomProxy?: boolean;
    /**
     * Gets or sets the proxy address.
     * @type {string}
     * @memberof ProxySettingsModel
     */
    proxyAddress?: string;
    /**
     * Gets or sets a value indicating whether the proxy requires authentication.
     * @type {boolean}
     * @memberof ProxySettingsModel
     */
    proxyAuthenticationRequired?: boolean;
    /**
     * Gets or sets the proxy domain.
     * @type {string}
     * @memberof ProxySettingsModel
     */
    proxyDomain?: string;
    /**
     * Gets or sets the proxy password.
     * @type {string}
     * @memberof ProxySettingsModel
     */
    proxyPassword?: string;
    /**
     * Gets or sets the proxy port.
     * @type {number}
     * @memberof ProxySettingsModel
     */
    proxyPort?: number;
    /**
     * Gets or sets the name of the proxy user.
     * @type {string}
     * @memberof ProxySettingsModel
     */
    proxyUsername?: string;
    /**
     * Gets or sets a value that indicates whether to bypass the proxy server for local addresses.
     * @type {boolean}
     * @memberof ProxySettingsModel
     */
    proxyByPassOnLocal?: boolean;
    /**
     * Gets or sets the proxy bypass text.
     * @type {string}
     * @memberof ProxySettingsModel
     */
    proxyByPassText?: string;
    /**
     * Gets or sets an value for proxy external communication
     * @type {boolean}
     * @memberof ProxySettingsModel
     */
    usePolicyProxyForExternalCommunication?: boolean;
}

/**
 * Check if a given object implements the ProxySettingsModel interface.
 */
export function instanceOfProxySettingsModel(value: object): boolean {
    return true;
}

export function ProxySettingsModelFromJSON(json: any): ProxySettingsModel {
    return ProxySettingsModelFromJSONTyped(json, false);
}

export function ProxySettingsModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ProxySettingsModel {
    if (json == null) {
        return json;
    }
    return {
        
        'proxyByPassList': json['ProxyByPassList'] == null ? undefined : json['ProxyByPassList'],
        'enableCustomProxy': json['EnableCustomProxy'] == null ? undefined : json['EnableCustomProxy'],
        'proxyAddress': json['ProxyAddress'] == null ? undefined : json['ProxyAddress'],
        'proxyAuthenticationRequired': json['ProxyAuthenticationRequired'] == null ? undefined : json['ProxyAuthenticationRequired'],
        'proxyDomain': json['ProxyDomain'] == null ? undefined : json['ProxyDomain'],
        'proxyPassword': json['ProxyPassword'] == null ? undefined : json['ProxyPassword'],
        'proxyPort': json['ProxyPort'] == null ? undefined : json['ProxyPort'],
        'proxyUsername': json['ProxyUsername'] == null ? undefined : json['ProxyUsername'],
        'proxyByPassOnLocal': json['ProxyByPassOnLocal'] == null ? undefined : json['ProxyByPassOnLocal'],
        'proxyByPassText': json['ProxyByPassText'] == null ? undefined : json['ProxyByPassText'],
        'usePolicyProxyForExternalCommunication': json['UsePolicyProxyForExternalCommunication'] == null ? undefined : json['UsePolicyProxyForExternalCommunication'],
    };
}

export function ProxySettingsModelToJSON(value?: ProxySettingsModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'ProxyByPassList': value['proxyByPassList'],
        'EnableCustomProxy': value['enableCustomProxy'],
        'ProxyAddress': value['proxyAddress'],
        'ProxyAuthenticationRequired': value['proxyAuthenticationRequired'],
        'ProxyDomain': value['proxyDomain'],
        'ProxyPassword': value['proxyPassword'],
        'ProxyPort': value['proxyPort'],
        'ProxyUsername': value['proxyUsername'],
        'ProxyByPassOnLocal': value['proxyByPassOnLocal'],
        'ProxyByPassText': value['proxyByPassText'],
        'UsePolicyProxyForExternalCommunication': value['usePolicyProxyForExternalCommunication'],
    };
}

