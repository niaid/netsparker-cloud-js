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
import { exists } from '../runtime';
/**
 * @export
 */
export const FormAuthenticationPersonaOtpTypeEnum = {
    Totp: 'Totp',
    Hotp: 'Hotp'
};
/**
 * @export
 */
export const FormAuthenticationPersonaAlgorithmEnum = {
    Sha1: 'Sha1',
    Sha256: 'Sha256',
    Sha512: 'Sha512'
};
/**
 * @export
 */
export const FormAuthenticationPersonaFormAuthTypeEnum = {
    Manual: 'Manual',
    Integration: 'Integration'
};
/**
 * @export
 */
export const FormAuthenticationPersonaVersionEnum = {
    V1: 'V1',
    V2: 'V2'
};
/**
 * Check if a given object implements the FormAuthenticationPersona interface.
 */
export function instanceOfFormAuthenticationPersona(value) {
    let isInstance = true;
    return isInstance;
}
export function FormAuthenticationPersonaFromJSON(json) {
    return FormAuthenticationPersonaFromJSONTyped(json, false);
}
export function FormAuthenticationPersonaFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'isActive': !exists(json, 'IsActive') ? undefined : json['IsActive'],
        'password': !exists(json, 'Password') ? undefined : json['Password'],
        'userName': !exists(json, 'UserName') ? undefined : json['UserName'],
        'otpType': !exists(json, 'OtpType') ? undefined : json['OtpType'],
        'secretKey': !exists(json, 'SecretKey') ? undefined : json['SecretKey'],
        'digit': !exists(json, 'Digit') ? undefined : json['Digit'],
        'period': !exists(json, 'Period') ? undefined : json['Period'],
        'algorithm': !exists(json, 'Algorithm') ? undefined : json['Algorithm'],
        'formAuthType': !exists(json, 'FormAuthType') ? undefined : json['FormAuthType'],
        'integrationId': !exists(json, 'IntegrationId') ? undefined : json['IntegrationId'],
        'version': !exists(json, 'Version') ? undefined : json['Version'],
        'secretEngine': !exists(json, 'SecretEngine') ? undefined : json['SecretEngine'],
        'secret': !exists(json, 'Secret') ? undefined : json['Secret'],
        'useStaticUsername': !exists(json, 'UseStaticUsername') ? undefined : json['UseStaticUsername'],
        'staticUsername': !exists(json, 'StaticUsername') ? undefined : json['StaticUsername'],
        'usernameKey': !exists(json, 'UsernameKey') ? undefined : json['UsernameKey'],
        'passwordKey': !exists(json, 'PasswordKey') ? undefined : json['PasswordKey'],
        'cyberArkUseStaticUsername': !exists(json, 'CyberArkUseStaticUsername') ? undefined : json['CyberArkUseStaticUsername'],
        'cyberArkStaticUsername': !exists(json, 'CyberArkStaticUsername') ? undefined : json['CyberArkStaticUsername'],
        'cyberArkUserNameQuery': !exists(json, 'CyberArkUserNameQuery') ? undefined : json['CyberArkUserNameQuery'],
        'cyberArkPasswordQuery': !exists(json, 'CyberArkPasswordQuery') ? undefined : json['CyberArkPasswordQuery'],
        'azureUseStaticUsername': !exists(json, 'AzureUseStaticUsername') ? undefined : json['AzureUseStaticUsername'],
        'azureStaticUsername': !exists(json, 'AzureStaticUsername') ? undefined : json['AzureStaticUsername'],
        'azureSecret': !exists(json, 'AzureSecret') ? undefined : json['AzureSecret'],
        'azureVaultName': !exists(json, 'AzureVaultName') ? undefined : json['AzureVaultName'],
        'azureUsernameKey': !exists(json, 'AzureUsernameKey') ? undefined : json['AzureUsernameKey'],
        'azurePasswordKey': !exists(json, 'AzurePasswordKey') ? undefined : json['AzurePasswordKey'],
        'originalUserName': !exists(json, 'OriginalUserName') ? undefined : json['OriginalUserName'],
        'isReplacedCredentials': !exists(json, 'IsReplacedCredentials') ? undefined : json['IsReplacedCredentials'],
        'index': !exists(json, 'Index') ? undefined : json['Index'],
    };
}
export function FormAuthenticationPersonaToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'IsActive': value.isActive,
        'Password': value.password,
        'UserName': value.userName,
        'OtpType': value.otpType,
        'SecretKey': value.secretKey,
        'Digit': value.digit,
        'Period': value.period,
        'Algorithm': value.algorithm,
        'FormAuthType': value.formAuthType,
        'IntegrationId': value.integrationId,
        'Version': value.version,
        'SecretEngine': value.secretEngine,
        'Secret': value.secret,
        'UseStaticUsername': value.useStaticUsername,
        'StaticUsername': value.staticUsername,
        'UsernameKey': value.usernameKey,
        'PasswordKey': value.passwordKey,
        'CyberArkUseStaticUsername': value.cyberArkUseStaticUsername,
        'CyberArkStaticUsername': value.cyberArkStaticUsername,
        'CyberArkUserNameQuery': value.cyberArkUserNameQuery,
        'CyberArkPasswordQuery': value.cyberArkPasswordQuery,
        'AzureUseStaticUsername': value.azureUseStaticUsername,
        'AzureStaticUsername': value.azureStaticUsername,
        'AzureSecret': value.azureSecret,
        'AzureVaultName': value.azureVaultName,
        'AzureUsernameKey': value.azureUsernameKey,
        'AzurePasswordKey': value.azurePasswordKey,
        'OriginalUserName': value.originalUserName,
        'IsReplacedCredentials': value.isReplacedCredentials,
        'Index': value.index,
    };
}
//# sourceMappingURL=FormAuthenticationPersona.js.map