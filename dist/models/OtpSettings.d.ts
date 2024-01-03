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
 * Represents otp settings
 * @export
 * @interface OtpSettings
 */
export interface OtpSettings {
    /**
     * Gets or sets OtpType.
     * @type {string}
     * @memberof OtpSettings
     */
    otpType?: OtpSettingsOtpTypeEnum;
    /**
     * Gets or sets secret key.
     * @type {string}
     * @memberof OtpSettings
     */
    secretKey?: string;
    /**
     * Gets or sets digit.
     * @type {number}
     * @memberof OtpSettings
     */
    digit?: number;
    /**
     * Gets or sets period (seconds).
     * @type {number}
     * @memberof OtpSettings
     */
    period?: number;
    /**
     * Gets or sets hash algorithm.
     * @type {string}
     * @memberof OtpSettings
     */
    algorithm?: OtpSettingsAlgorithmEnum;
}
/**
 * @export
 */
export declare const OtpSettingsOtpTypeEnum: {
    readonly Totp: "Totp";
    readonly Hotp: "Hotp";
};
export type OtpSettingsOtpTypeEnum = typeof OtpSettingsOtpTypeEnum[keyof typeof OtpSettingsOtpTypeEnum];
/**
 * @export
 */
export declare const OtpSettingsAlgorithmEnum: {
    readonly Sha1: "Sha1";
    readonly Sha256: "Sha256";
    readonly Sha512: "Sha512";
};
export type OtpSettingsAlgorithmEnum = typeof OtpSettingsAlgorithmEnum[keyof typeof OtpSettingsAlgorithmEnum];
/**
 * Check if a given object implements the OtpSettings interface.
 */
export declare function instanceOfOtpSettings(value: object): boolean;
export declare function OtpSettingsFromJSON(json: any): OtpSettings;
export declare function OtpSettingsFromJSONTyped(json: any, ignoreDiscriminator: boolean): OtpSettings;
export declare function OtpSettingsToJSON(value?: OtpSettings | null): any;