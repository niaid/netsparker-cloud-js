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
 * Scan Policy web storage settings
 * @export
 * @interface WebStorageSetting
 */
export interface WebStorageSetting {
    /**
     * Web storage key.
     * @type {string}
     * @memberof WebStorageSetting
     */
    key: string;
    /**
     * Web storage origin.
     * @type {string}
     * @memberof WebStorageSetting
     */
    origin?: string;
    /**
     * Web settings storage types
     * @type {string}
     * @memberof WebStorageSetting
     */
    type: WebStorageSettingTypeEnum;
    /**
     * Web storage value.
     * @type {string}
     * @memberof WebStorageSetting
     */
    value: string;
}
/**
 * @export
 */
export declare const WebStorageSettingTypeEnum: {
    readonly Local: "Local";
    readonly Session: "Session";
};
export type WebStorageSettingTypeEnum = typeof WebStorageSettingTypeEnum[keyof typeof WebStorageSettingTypeEnum];
/**
 * Check if a given object implements the WebStorageSetting interface.
 */
export declare function instanceOfWebStorageSetting(value: object): boolean;
export declare function WebStorageSettingFromJSON(json: any): WebStorageSetting;
export declare function WebStorageSettingFromJSONTyped(json: any, ignoreDiscriminator: boolean): WebStorageSetting;
export declare function WebStorageSettingToJSON(value?: WebStorageSetting | null): any;
