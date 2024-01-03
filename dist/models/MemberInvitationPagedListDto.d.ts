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
import type { MemberInvitationDto } from './MemberInvitationDto';
/**
 *
 * @export
 * @interface MemberInvitationPagedListDto
 */
export interface MemberInvitationPagedListDto {
    /**
     *
     * @type {number}
     * @memberof MemberInvitationPagedListDto
     */
    firstItemOnPage?: number;
    /**
     *
     * @type {boolean}
     * @memberof MemberInvitationPagedListDto
     */
    hasNextPage?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof MemberInvitationPagedListDto
     */
    hasPreviousPage?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof MemberInvitationPagedListDto
     */
    isFirstPage?: boolean;
    /**
     *
     * @type {boolean}
     * @memberof MemberInvitationPagedListDto
     */
    isLastPage?: boolean;
    /**
     *
     * @type {number}
     * @memberof MemberInvitationPagedListDto
     */
    lastItemOnPage?: number;
    /**
     *
     * @type {Array<MemberInvitationDto>}
     * @memberof MemberInvitationPagedListDto
     */
    list?: Array<MemberInvitationDto>;
    /**
     *
     * @type {number}
     * @memberof MemberInvitationPagedListDto
     */
    pageCount?: number;
    /**
     *
     * @type {number}
     * @memberof MemberInvitationPagedListDto
     */
    pageNumber?: number;
    /**
     *
     * @type {number}
     * @memberof MemberInvitationPagedListDto
     */
    pageSize?: number;
    /**
     *
     * @type {number}
     * @memberof MemberInvitationPagedListDto
     */
    totalItemCount?: number;
}
/**
 * Check if a given object implements the MemberInvitationPagedListDto interface.
 */
export declare function instanceOfMemberInvitationPagedListDto(value: object): boolean;
export declare function MemberInvitationPagedListDtoFromJSON(json: any): MemberInvitationPagedListDto;
export declare function MemberInvitationPagedListDtoFromJSONTyped(json: any, ignoreDiscriminator: boolean): MemberInvitationPagedListDto;
export declare function MemberInvitationPagedListDtoToJSON(value?: MemberInvitationPagedListDto | null): any;