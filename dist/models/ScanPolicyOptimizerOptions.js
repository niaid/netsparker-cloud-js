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
export const ScanPolicyOptimizerOptionsAppServerEnum = {
    All: 'All',
    Aspnet: 'Aspnet',
    Php: 'Php',
    Rails: 'Rails',
    Java: 'Java',
    Perl: 'Perl',
    Python: 'Python',
    NodeJs: 'NodeJs',
    Other: 'Other'
};
/**
 * @export
 */
export const ScanPolicyOptimizerOptionsDatabaseServerEnum = {
    All: 'All',
    MsSql: 'MsSql',
    MySql: 'MySql',
    Oracle: 'Oracle',
    PostgreSql: 'PostgreSql',
    MsAccess: 'MsAccess',
    HsqlDb: 'HsqlDb',
    Sqlite: 'Sqlite',
    MongoDb: 'MongoDb',
    Other: 'Other'
};
/**
 * @export
 */
export const ScanPolicyOptimizerOptionsDomParserPresetEnum = {
    None: 'None',
    Default: 'Default',
    Spa: 'Spa',
    LargeSpa: 'LargeSpa'
};
/**
 * @export
 */
export const ScanPolicyOptimizerOptionsOperatingSystemEnum = {
    All: 'All',
    Windows: 'Windows',
    Unix: 'Unix'
};
/**
 * @export
 */
export const ScanPolicyOptimizerOptionsSuggestionStatusEnum = {
    Always: 'Always',
    NotNow: 'NotNow',
    Never: 'Never'
};
/**
 * @export
 */
export const ScanPolicyOptimizerOptionsWebServerEnum = {
    All: 'All',
    Iis: 'Iis',
    Apache: 'Apache',
    ApacheTomcat: 'ApacheTomcat',
    Nginx: 'Nginx',
    Other: 'Other'
};
/**
 * Check if a given object implements the ScanPolicyOptimizerOptions interface.
 */
export function instanceOfScanPolicyOptimizerOptions(value) {
    let isInstance = true;
    return isInstance;
}
export function ScanPolicyOptimizerOptionsFromJSON(json) {
    return ScanPolicyOptimizerOptionsFromJSONTyped(json, false);
}
export function ScanPolicyOptimizerOptionsFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'appServer': !exists(json, 'AppServer') ? undefined : json['AppServer'],
        'databaseServer': !exists(json, 'DatabaseServer') ? undefined : json['DatabaseServer'],
        'directoryNameLimit': !exists(json, 'DirectoryNameLimit') ? undefined : json['DirectoryNameLimit'],
        'domParserPreset': !exists(json, 'DomParserPreset') ? undefined : json['DomParserPreset'],
        'hosts': !exists(json, 'Hosts') ? undefined : json['Hosts'],
        'isSharkEnabled': !exists(json, 'IsSharkEnabled') ? undefined : json['IsSharkEnabled'],
        'name': !exists(json, 'Name') ? undefined : json['Name'],
        'netsparkerHawkBaseUrl': !exists(json, 'NetsparkerHawkBaseUrl') ? undefined : json['NetsparkerHawkBaseUrl'],
        'operatingSystem': !exists(json, 'OperatingSystem') ? undefined : json['OperatingSystem'],
        'optimized': !exists(json, 'Optimized') ? undefined : json['Optimized'],
        'resourceFinders': !exists(json, 'ResourceFinders') ? undefined : json['ResourceFinders'],
        'suggestionStatus': !exists(json, 'SuggestionStatus') ? undefined : json['SuggestionStatus'],
        'webServer': !exists(json, 'WebServer') ? undefined : json['WebServer'],
    };
}
export function ScanPolicyOptimizerOptionsToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'AppServer': value.appServer,
        'DatabaseServer': value.databaseServer,
        'DirectoryNameLimit': value.directoryNameLimit,
        'DomParserPreset': value.domParserPreset,
        'Hosts': value.hosts,
        'IsSharkEnabled': value.isSharkEnabled,
        'Name': value.name,
        'NetsparkerHawkBaseUrl': value.netsparkerHawkBaseUrl,
        'OperatingSystem': value.operatingSystem,
        'Optimized': value.optimized,
        'ResourceFinders': value.resourceFinders,
        'SuggestionStatus': value.suggestionStatus,
        'WebServer': value.webServer,
    };
}
//# sourceMappingURL=ScanPolicyOptimizerOptions.js.map