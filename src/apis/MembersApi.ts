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


import * as runtime from '../runtime';
import type {
  BaseResponseApiModel,
  MemberApiModelListApiResult,
  MemberApiViewModel,
  MemberInvitationDto,
  MemberInvitationPagedListDto,
  NewMemberApiModel,
  NewMemberInvitationApiModel,
  TimezoneApiModel,
  UpdateMemberApiModel,
  UserApiTokenModel,
} from '../models/index';
import {
    BaseResponseApiModelFromJSON,
    BaseResponseApiModelToJSON,
    MemberApiModelListApiResultFromJSON,
    MemberApiModelListApiResultToJSON,
    MemberApiViewModelFromJSON,
    MemberApiViewModelToJSON,
    MemberInvitationDtoFromJSON,
    MemberInvitationDtoToJSON,
    MemberInvitationPagedListDtoFromJSON,
    MemberInvitationPagedListDtoToJSON,
    NewMemberApiModelFromJSON,
    NewMemberApiModelToJSON,
    NewMemberInvitationApiModelFromJSON,
    NewMemberInvitationApiModelToJSON,
    TimezoneApiModelFromJSON,
    TimezoneApiModelToJSON,
    UpdateMemberApiModelFromJSON,
    UpdateMemberApiModelToJSON,
    UserApiTokenModelFromJSON,
    UserApiTokenModelToJSON,
} from '../models/index';

export interface MembersDeleteRequest {
    id: string;
}

export interface MembersDeleteInvitationRequest {
    email: string;
}

export interface MembersGetRequest {
    id: string;
}

export interface MembersGetApiTokenRequest {
    email: string;
}

export interface MembersGetByEmailRequest {
    email: string;
}

export interface MembersGetInvitationRequest {
    invitationId: string;
}

export interface MembersInvitationListRequest {
    page?: number;
    pageSize?: number;
}

export interface MembersListRequest {
    page?: number;
    pageSize?: number;
}

export interface MembersNewRequest {
    model: NewMemberApiModel;
}

export interface MembersNewInvitationRequest {
    model: NewMemberInvitationApiModel;
}

export interface MembersSendInvitationEmailRequest {
    invitationId: string;
}

export interface MembersUpdateRequest {
    model: UpdateMemberApiModel;
}

/**
 * 
 */
export class MembersApi extends runtime.BaseAPI {

    /**
     * Deletes a member
     */
    async membersDeleteRaw(requestParameters: MembersDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<string>> {
        if (requestParameters.id === null || requestParameters.id === undefined) {
            throw new runtime.RequiredError('id','Required parameter requestParameters.id was null or undefined when calling membersDelete.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/members/delete/{id}`.replace(`{${"id"}}`, encodeURIComponent(String(requestParameters.id))),
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        if (this.isJsonMime(response.headers.get('content-type'))) {
            return new runtime.JSONApiResponse<string>(response);
        } else {
            return new runtime.TextApiResponse(response) as any;
        }
    }

    /**
     * Deletes a member
     */
    async membersDelete(requestParameters: MembersDeleteRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<string> {
        const response = await this.membersDeleteRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Deletes member invitation
     */
    async membersDeleteInvitationRaw(requestParameters: MembersDeleteInvitationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.email === null || requestParameters.email === undefined) {
            throw new runtime.RequiredError('email','Required parameter requestParameters.email was null or undefined when calling membersDeleteInvitation.');
        }

        const queryParameters: any = {};

        if (requestParameters.email !== undefined) {
            queryParameters['email'] = requestParameters.email;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/members/deleteinvitation`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Deletes member invitation
     */
    async membersDeleteInvitation(requestParameters: MembersDeleteInvitationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.membersDeleteInvitationRaw(requestParameters, initOverrides);
    }

    /**
     * Gets the member by the specified id.
     */
    async membersGetRaw(requestParameters: MembersGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<MemberApiViewModel>> {
        if (requestParameters.id === null || requestParameters.id === undefined) {
            throw new runtime.RequiredError('id','Required parameter requestParameters.id was null or undefined when calling membersGet.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/members/get/{id}`.replace(`{${"id"}}`, encodeURIComponent(String(requestParameters.id))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => MemberApiViewModelFromJSON(jsonValue));
    }

    /**
     * Gets the member by the specified id.
     */
    async membersGet(requestParameters: MembersGetRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<MemberApiViewModel> {
        const response = await this.membersGetRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets user api token.
     */
    async membersGetApiTokenRaw(requestParameters: MembersGetApiTokenRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<UserApiTokenModel>> {
        if (requestParameters.email === null || requestParameters.email === undefined) {
            throw new runtime.RequiredError('email','Required parameter requestParameters.email was null or undefined when calling membersGetApiToken.');
        }

        const queryParameters: any = {};

        if (requestParameters.email !== undefined) {
            queryParameters['email'] = requestParameters.email;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/members/getapitoken`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => UserApiTokenModelFromJSON(jsonValue));
    }

    /**
     * Gets user api token.
     */
    async membersGetApiToken(requestParameters: MembersGetApiTokenRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<UserApiTokenModel> {
        const response = await this.membersGetApiTokenRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets user by email.
     */
    async membersGetByEmailRaw(requestParameters: MembersGetByEmailRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<MemberApiViewModel>> {
        if (requestParameters.email === null || requestParameters.email === undefined) {
            throw new runtime.RequiredError('email','Required parameter requestParameters.email was null or undefined when calling membersGetByEmail.');
        }

        const queryParameters: any = {};

        if (requestParameters.email !== undefined) {
            queryParameters['email'] = requestParameters.email;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/members/getbyemail`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => MemberApiViewModelFromJSON(jsonValue));
    }

    /**
     * Gets user by email.
     */
    async membersGetByEmail(requestParameters: MembersGetByEmailRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<MemberApiViewModel> {
        const response = await this.membersGetByEmailRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the member invitation by the specified id.
     */
    async membersGetInvitationRaw(requestParameters: MembersGetInvitationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<MemberInvitationDto>> {
        if (requestParameters.invitationId === null || requestParameters.invitationId === undefined) {
            throw new runtime.RequiredError('invitationId','Required parameter requestParameters.invitationId was null or undefined when calling membersGetInvitation.');
        }

        const queryParameters: any = {};

        if (requestParameters.invitationId !== undefined) {
            queryParameters['invitationId'] = requestParameters.invitationId;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/members/getinvitation`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => MemberInvitationDtoFromJSON(jsonValue));
    }

    /**
     * Gets the member invitation by the specified id.
     */
    async membersGetInvitation(requestParameters: MembersGetInvitationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<MemberInvitationDto> {
        const response = await this.membersGetInvitationRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets a list all of the time zones.
     */
    async membersGetTimezonesRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<TimezoneApiModel>> {
        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/members/gettimezones`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => TimezoneApiModelFromJSON(jsonValue));
    }

    /**
     * Gets a list all of the time zones.
     */
    async membersGetTimezones(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<TimezoneApiModel> {
        const response = await this.membersGetTimezonesRaw(initOverrides);
        return await response.value();
    }

    /**
     * Gets the list of members.
     */
    async membersInvitationListRaw(requestParameters: MembersInvitationListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<MemberInvitationPagedListDto>> {
        const queryParameters: any = {};

        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }

        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/members/invitationlist`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => MemberInvitationPagedListDtoFromJSON(jsonValue));
    }

    /**
     * Gets the list of members.
     */
    async membersInvitationList(requestParameters: MembersInvitationListRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<MemberInvitationPagedListDto> {
        const response = await this.membersInvitationListRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Gets the list of members.
     */
    async membersListRaw(requestParameters: MembersListRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<MemberApiModelListApiResult>> {
        const queryParameters: any = {};

        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }

        if (requestParameters.pageSize !== undefined) {
            queryParameters['pageSize'] = requestParameters.pageSize;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/members/list`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => MemberApiModelListApiResultFromJSON(jsonValue));
    }

    /**
     * Gets the list of members.
     */
    async membersList(requestParameters: MembersListRequest = {}, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<MemberApiModelListApiResult> {
        const response = await this.membersListRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Creates a new member.
     */
    async membersNewRaw(requestParameters: MembersNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<MemberApiViewModel>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling membersNew.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/members/new`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: NewMemberApiModelToJSON(requestParameters.model),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => MemberApiViewModelFromJSON(jsonValue));
    }

    /**
     * Creates a new member.
     */
    async membersNew(requestParameters: MembersNewRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<MemberApiViewModel> {
        const response = await this.membersNewRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Creates a new member invitation
     */
    async membersNewInvitationRaw(requestParameters: MembersNewInvitationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling membersNewInvitation.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/members/newinvitation`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: NewMemberInvitationApiModelToJSON(requestParameters.model),
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Creates a new member invitation
     */
    async membersNewInvitation(requestParameters: MembersNewInvitationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.membersNewInvitationRaw(requestParameters, initOverrides);
    }

    /**
     * Sends member invitation email
     */
    async membersSendInvitationEmailRaw(requestParameters: MembersSendInvitationEmailRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.invitationId === null || requestParameters.invitationId === undefined) {
            throw new runtime.RequiredError('invitationId','Required parameter requestParameters.invitationId was null or undefined when calling membersSendInvitationEmail.');
        }

        const queryParameters: any = {};

        if (requestParameters.invitationId !== undefined) {
            queryParameters['invitationId'] = requestParameters.invitationId;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/1.0/members/sendinvitationemail`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Sends member invitation email
     */
    async membersSendInvitationEmail(requestParameters: MembersSendInvitationEmailRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.membersSendInvitationEmailRaw(requestParameters, initOverrides);
    }

    /**
     * Updates a member
     */
    async membersUpdateRaw(requestParameters: MembersUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<MemberApiViewModel>> {
        if (requestParameters.model === null || requestParameters.model === undefined) {
            throw new runtime.RequiredError('model','Required parameter requestParameters.model was null or undefined when calling membersUpdate.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/1.0/members/update`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: UpdateMemberApiModelToJSON(requestParameters.model),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => MemberApiViewModelFromJSON(jsonValue));
    }

    /**
     * Updates a member
     */
    async membersUpdate(requestParameters: MembersUpdateRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<MemberApiViewModel> {
        const response = await this.membersUpdateRaw(requestParameters, initOverrides);
        return await response.value();
    }

}