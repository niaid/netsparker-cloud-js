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
 * Tag View Model
 * @export
 * @interface TagViewModel
 */
export interface TagViewModel {
    /**
     * Id
     * @type {string}
     * @memberof TagViewModel
     */
    id?: string;
    /**
     * Value
     * @type {string}
     * @memberof TagViewModel
     */
    value?: string;
}
/**
 * Check if a given object implements the TagViewModel interface.
 */
export declare function instanceOfTagViewModel(value: object): boolean;
export declare function TagViewModelFromJSON(json: any): TagViewModel;
export declare function TagViewModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): TagViewModel;
export declare function TagViewModelToJSON(value?: TagViewModel | null): any;
