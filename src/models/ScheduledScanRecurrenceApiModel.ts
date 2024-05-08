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
 * Scheduled scan recurrence view model.
 * @export
 * @interface ScheduledScanRecurrenceApiModel
 */
export interface ScheduledScanRecurrenceApiModel {
    /**
     * The {Invicti.Dates.Recurring.Enums.RepeatTypes}.
     * @type {string}
     * @memberof ScheduledScanRecurrenceApiModel
     */
    repeatType?: ScheduledScanRecurrenceApiModelRepeatTypeEnum;
    /**
     * The interval.
     * @type {number}
     * @memberof ScheduledScanRecurrenceApiModel
     */
    interval?: number;
    /**
     * The ending type.
     * @type {string}
     * @memberof ScheduledScanRecurrenceApiModel
     */
    endingType?: ScheduledScanRecurrenceApiModelEndingTypeEnum;
    /**
     * The day of weeks.
     * @type {Array<string>}
     * @memberof ScheduledScanRecurrenceApiModel
     */
    daysOfWeek?: Array<ScheduledScanRecurrenceApiModelDaysOfWeekEnum>;
    /**
     * The months of year.
     * @type {Array<string>}
     * @memberof ScheduledScanRecurrenceApiModel
     */
    monthsOfYear?: Array<ScheduledScanRecurrenceApiModelMonthsOfYearEnum>;
    /**
     * The ordinals.
     * @type {string}
     * @memberof ScheduledScanRecurrenceApiModel
     */
    ordinal?: ScheduledScanRecurrenceApiModelOrdinalEnum;
    /**
     * The ending date.
     * @type {string}
     * @memberof ScheduledScanRecurrenceApiModel
     */
    endOn?: string;
    /**
     * The limit of the scheduled scan executions.
     * @type {number}
     * @memberof ScheduledScanRecurrenceApiModel
     */
    endOnOccurences?: number;
    /**
     * The day of month.
     * @type {number}
     * @memberof ScheduledScanRecurrenceApiModel
     */
    dayOfMonth?: number;
    /**
     * The recurrence builder.
     * @type {string}
     * @memberof ScheduledScanRecurrenceApiModel
     */
    dayOfWeek?: ScheduledScanRecurrenceApiModelDayOfWeekEnum;
}


/**
 * @export
 */
export const ScheduledScanRecurrenceApiModelRepeatTypeEnum = {
    Days: 'Days',
    Weeks: 'Weeks',
    Months: 'Months',
    Years: 'Years'
} as const;
export type ScheduledScanRecurrenceApiModelRepeatTypeEnum = typeof ScheduledScanRecurrenceApiModelRepeatTypeEnum[keyof typeof ScheduledScanRecurrenceApiModelRepeatTypeEnum];

/**
 * @export
 */
export const ScheduledScanRecurrenceApiModelEndingTypeEnum = {
    Never: 'Never',
    Date: 'Date',
    Occurences: 'Occurences'
} as const;
export type ScheduledScanRecurrenceApiModelEndingTypeEnum = typeof ScheduledScanRecurrenceApiModelEndingTypeEnum[keyof typeof ScheduledScanRecurrenceApiModelEndingTypeEnum];

/**
 * @export
 */
export const ScheduledScanRecurrenceApiModelDaysOfWeekEnum = {
    Sunday: 'Sunday',
    Monday: 'Monday',
    Tuesday: 'Tuesday',
    Wednesday: 'Wednesday',
    Thursday: 'Thursday',
    Friday: 'Friday',
    Saturday: 'Saturday'
} as const;
export type ScheduledScanRecurrenceApiModelDaysOfWeekEnum = typeof ScheduledScanRecurrenceApiModelDaysOfWeekEnum[keyof typeof ScheduledScanRecurrenceApiModelDaysOfWeekEnum];

/**
 * @export
 */
export const ScheduledScanRecurrenceApiModelMonthsOfYearEnum = {
    January: 'January',
    February: 'February',
    March: 'March',
    April: 'April',
    May: 'May',
    June: 'June',
    July: 'July',
    August: 'August',
    September: 'September',
    October: 'October',
    November: 'November',
    December: 'December'
} as const;
export type ScheduledScanRecurrenceApiModelMonthsOfYearEnum = typeof ScheduledScanRecurrenceApiModelMonthsOfYearEnum[keyof typeof ScheduledScanRecurrenceApiModelMonthsOfYearEnum];

/**
 * @export
 */
export const ScheduledScanRecurrenceApiModelOrdinalEnum = {
    First: 'First',
    Second: 'Second',
    Third: 'Third',
    Fourth: 'Fourth',
    Last: 'Last'
} as const;
export type ScheduledScanRecurrenceApiModelOrdinalEnum = typeof ScheduledScanRecurrenceApiModelOrdinalEnum[keyof typeof ScheduledScanRecurrenceApiModelOrdinalEnum];

/**
 * @export
 */
export const ScheduledScanRecurrenceApiModelDayOfWeekEnum = {
    Sunday: 'Sunday',
    Monday: 'Monday',
    Tuesday: 'Tuesday',
    Wednesday: 'Wednesday',
    Thursday: 'Thursday',
    Friday: 'Friday',
    Saturday: 'Saturday'
} as const;
export type ScheduledScanRecurrenceApiModelDayOfWeekEnum = typeof ScheduledScanRecurrenceApiModelDayOfWeekEnum[keyof typeof ScheduledScanRecurrenceApiModelDayOfWeekEnum];


/**
 * Check if a given object implements the ScheduledScanRecurrenceApiModel interface.
 */
export function instanceOfScheduledScanRecurrenceApiModel(value: object): boolean {
    return true;
}

export function ScheduledScanRecurrenceApiModelFromJSON(json: any): ScheduledScanRecurrenceApiModel {
    return ScheduledScanRecurrenceApiModelFromJSONTyped(json, false);
}

export function ScheduledScanRecurrenceApiModelFromJSONTyped(json: any, ignoreDiscriminator: boolean): ScheduledScanRecurrenceApiModel {
    if (json == null) {
        return json;
    }
    return {
        
        'repeatType': json['RepeatType'] == null ? undefined : json['RepeatType'],
        'interval': json['Interval'] == null ? undefined : json['Interval'],
        'endingType': json['EndingType'] == null ? undefined : json['EndingType'],
        'daysOfWeek': json['DaysOfWeek'] == null ? undefined : json['DaysOfWeek'],
        'monthsOfYear': json['MonthsOfYear'] == null ? undefined : json['MonthsOfYear'],
        'ordinal': json['Ordinal'] == null ? undefined : json['Ordinal'],
        'endOn': json['EndOn'] == null ? undefined : json['EndOn'],
        'endOnOccurences': json['EndOnOccurences'] == null ? undefined : json['EndOnOccurences'],
        'dayOfMonth': json['DayOfMonth'] == null ? undefined : json['DayOfMonth'],
        'dayOfWeek': json['DayOfWeek'] == null ? undefined : json['DayOfWeek'],
    };
}

export function ScheduledScanRecurrenceApiModelToJSON(value?: ScheduledScanRecurrenceApiModel | null): any {
    if (value == null) {
        return value;
    }
    return {
        
        'RepeatType': value['repeatType'],
        'Interval': value['interval'],
        'EndingType': value['endingType'],
        'DaysOfWeek': value['daysOfWeek'],
        'MonthsOfYear': value['monthsOfYear'],
        'Ordinal': value['ordinal'],
        'EndOn': value['endOn'],
        'EndOnOccurences': value['endOnOccurences'],
        'DayOfMonth': value['dayOfMonth'],
        'DayOfWeek': value['dayOfWeek'],
    };
}

