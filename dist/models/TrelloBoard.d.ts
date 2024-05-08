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
 *
 * @export
 * @interface TrelloBoard
 */
export interface TrelloBoard {
    /**
     *
     * @type {boolean}
     * @memberof TrelloBoard
     */
    closed?: boolean;
    /**
     *
     * @type {string}
     * @memberof TrelloBoard
     */
    id?: string;
    /**
     *
     * @type {boolean}
     * @memberof TrelloBoard
     */
    readonly isActive?: boolean;
    /**
     *
     * @type {string}
     * @memberof TrelloBoard
     */
    name?: string;
    /**
     *
     * @type {string}
     * @memberof TrelloBoard
     */
    shortUrl?: string;
}
/**
 * Check if a given object implements the TrelloBoard interface.
 */
export declare function instanceOfTrelloBoard(value: object): boolean;
export declare function TrelloBoardFromJSON(json: any): TrelloBoard;
export declare function TrelloBoardFromJSONTyped(json: any, ignoreDiscriminator: boolean): TrelloBoard;
export declare function TrelloBoardToJSON(value?: Omit<TrelloBoard, 'IsActive'> | null): any;
