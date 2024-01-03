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
import type { CustomScriptPageViewModel } from './CustomScriptPageViewModel';
/**
 * Represents the of an Authentication Profile Model.
 * @export
 * @interface AuthenticationProfileViewModel
 */
export interface AuthenticationProfileViewModel {
    /**
     * Id
     * @type {string}
     * @memberof AuthenticationProfileViewModel
     */
    id?: string;
    /**
     * The Name
     * @type {string}
     * @memberof AuthenticationProfileViewModel
     */
    name: string;
    /**
     * The Triggered Url.
     * @type {string}
     * @memberof AuthenticationProfileViewModel
     */
    triggeredUrl: string;
    /**
     * The Login Url.
     * @type {string}
     * @memberof AuthenticationProfileViewModel
     */
    loginUrl: string;
    /**
     * The custom scripts.
     * @type {Array<CustomScriptPageViewModel>}
     * @memberof AuthenticationProfileViewModel
     */
    customScripts: Array<CustomScriptPageViewModel>;
}
/**
 * Check if a given object implements the AuthenticationProfileViewModel interface.
 */
export declare function instanceOfAuthenticationProfileViewModel(value: object): boolean;
export declare function AuthenticationProfileViewModelFromJSON(json: any): AuthenticationProfileViewModel;
export declare function AuthenticationProfileViewModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): AuthenticationProfileViewModel;
export declare function AuthenticationProfileViewModelToJSON(value?: AuthenticationProfileViewModel | null): any;
