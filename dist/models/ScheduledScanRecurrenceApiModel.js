"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScheduledScanRecurrenceApiModelToJSON = exports.ScheduledScanRecurrenceApiModelFromJSONTyped = exports.ScheduledScanRecurrenceApiModelFromJSON = exports.instanceOfScheduledScanRecurrenceApiModel = exports.ScheduledScanRecurrenceApiModelDayOfWeekEnum = exports.ScheduledScanRecurrenceApiModelOrdinalEnum = exports.ScheduledScanRecurrenceApiModelMonthsOfYearEnum = exports.ScheduledScanRecurrenceApiModelDaysOfWeekEnum = exports.ScheduledScanRecurrenceApiModelEndingTypeEnum = exports.ScheduledScanRecurrenceApiModelRepeatTypeEnum = void 0;
const runtime_1 = require("../runtime");
/**
* @export
* @enum {string}
*/
var ScheduledScanRecurrenceApiModelRepeatTypeEnum;
(function (ScheduledScanRecurrenceApiModelRepeatTypeEnum) {
    ScheduledScanRecurrenceApiModelRepeatTypeEnum["Days"] = "Days";
    ScheduledScanRecurrenceApiModelRepeatTypeEnum["Weeks"] = "Weeks";
    ScheduledScanRecurrenceApiModelRepeatTypeEnum["Months"] = "Months";
    ScheduledScanRecurrenceApiModelRepeatTypeEnum["Years"] = "Years";
})(ScheduledScanRecurrenceApiModelRepeatTypeEnum = exports.ScheduledScanRecurrenceApiModelRepeatTypeEnum || (exports.ScheduledScanRecurrenceApiModelRepeatTypeEnum = {}));
/**
* @export
* @enum {string}
*/
var ScheduledScanRecurrenceApiModelEndingTypeEnum;
(function (ScheduledScanRecurrenceApiModelEndingTypeEnum) {
    ScheduledScanRecurrenceApiModelEndingTypeEnum["Never"] = "Never";
    ScheduledScanRecurrenceApiModelEndingTypeEnum["Date"] = "Date";
    ScheduledScanRecurrenceApiModelEndingTypeEnum["Occurences"] = "Occurences";
})(ScheduledScanRecurrenceApiModelEndingTypeEnum = exports.ScheduledScanRecurrenceApiModelEndingTypeEnum || (exports.ScheduledScanRecurrenceApiModelEndingTypeEnum = {}));
/**
* @export
* @enum {string}
*/
var ScheduledScanRecurrenceApiModelDaysOfWeekEnum;
(function (ScheduledScanRecurrenceApiModelDaysOfWeekEnum) {
    ScheduledScanRecurrenceApiModelDaysOfWeekEnum["Sunday"] = "Sunday";
    ScheduledScanRecurrenceApiModelDaysOfWeekEnum["Monday"] = "Monday";
    ScheduledScanRecurrenceApiModelDaysOfWeekEnum["Tuesday"] = "Tuesday";
    ScheduledScanRecurrenceApiModelDaysOfWeekEnum["Wednesday"] = "Wednesday";
    ScheduledScanRecurrenceApiModelDaysOfWeekEnum["Thursday"] = "Thursday";
    ScheduledScanRecurrenceApiModelDaysOfWeekEnum["Friday"] = "Friday";
    ScheduledScanRecurrenceApiModelDaysOfWeekEnum["Saturday"] = "Saturday";
})(ScheduledScanRecurrenceApiModelDaysOfWeekEnum = exports.ScheduledScanRecurrenceApiModelDaysOfWeekEnum || (exports.ScheduledScanRecurrenceApiModelDaysOfWeekEnum = {}));
/**
* @export
* @enum {string}
*/
var ScheduledScanRecurrenceApiModelMonthsOfYearEnum;
(function (ScheduledScanRecurrenceApiModelMonthsOfYearEnum) {
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["January"] = "January";
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["February"] = "February";
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["March"] = "March";
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["April"] = "April";
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["May"] = "May";
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["June"] = "June";
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["July"] = "July";
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["August"] = "August";
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["September"] = "September";
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["October"] = "October";
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["November"] = "November";
    ScheduledScanRecurrenceApiModelMonthsOfYearEnum["December"] = "December";
})(ScheduledScanRecurrenceApiModelMonthsOfYearEnum = exports.ScheduledScanRecurrenceApiModelMonthsOfYearEnum || (exports.ScheduledScanRecurrenceApiModelMonthsOfYearEnum = {}));
/**
* @export
* @enum {string}
*/
var ScheduledScanRecurrenceApiModelOrdinalEnum;
(function (ScheduledScanRecurrenceApiModelOrdinalEnum) {
    ScheduledScanRecurrenceApiModelOrdinalEnum["First"] = "First";
    ScheduledScanRecurrenceApiModelOrdinalEnum["Second"] = "Second";
    ScheduledScanRecurrenceApiModelOrdinalEnum["Third"] = "Third";
    ScheduledScanRecurrenceApiModelOrdinalEnum["Fourth"] = "Fourth";
    ScheduledScanRecurrenceApiModelOrdinalEnum["Last"] = "Last";
})(ScheduledScanRecurrenceApiModelOrdinalEnum = exports.ScheduledScanRecurrenceApiModelOrdinalEnum || (exports.ScheduledScanRecurrenceApiModelOrdinalEnum = {}));
/**
* @export
* @enum {string}
*/
var ScheduledScanRecurrenceApiModelDayOfWeekEnum;
(function (ScheduledScanRecurrenceApiModelDayOfWeekEnum) {
    ScheduledScanRecurrenceApiModelDayOfWeekEnum["Sunday"] = "Sunday";
    ScheduledScanRecurrenceApiModelDayOfWeekEnum["Monday"] = "Monday";
    ScheduledScanRecurrenceApiModelDayOfWeekEnum["Tuesday"] = "Tuesday";
    ScheduledScanRecurrenceApiModelDayOfWeekEnum["Wednesday"] = "Wednesday";
    ScheduledScanRecurrenceApiModelDayOfWeekEnum["Thursday"] = "Thursday";
    ScheduledScanRecurrenceApiModelDayOfWeekEnum["Friday"] = "Friday";
    ScheduledScanRecurrenceApiModelDayOfWeekEnum["Saturday"] = "Saturday";
})(ScheduledScanRecurrenceApiModelDayOfWeekEnum = exports.ScheduledScanRecurrenceApiModelDayOfWeekEnum || (exports.ScheduledScanRecurrenceApiModelDayOfWeekEnum = {}));
/**
 * Check if a given object implements the ScheduledScanRecurrenceApiModel interface.
 */
function instanceOfScheduledScanRecurrenceApiModel(value) {
    let isInstance = true;
    return isInstance;
}
exports.instanceOfScheduledScanRecurrenceApiModel = instanceOfScheduledScanRecurrenceApiModel;
function ScheduledScanRecurrenceApiModelFromJSON(json) {
    return ScheduledScanRecurrenceApiModelFromJSONTyped(json, false);
}
exports.ScheduledScanRecurrenceApiModelFromJSON = ScheduledScanRecurrenceApiModelFromJSON;
function ScheduledScanRecurrenceApiModelFromJSONTyped(json, ignoreDiscriminator) {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        'repeatType': !(0, runtime_1.exists)(json, 'RepeatType') ? undefined : json['RepeatType'],
        'interval': !(0, runtime_1.exists)(json, 'Interval') ? undefined : json['Interval'],
        'endingType': !(0, runtime_1.exists)(json, 'EndingType') ? undefined : json['EndingType'],
        'daysOfWeek': !(0, runtime_1.exists)(json, 'DaysOfWeek') ? undefined : json['DaysOfWeek'],
        'monthsOfYear': !(0, runtime_1.exists)(json, 'MonthsOfYear') ? undefined : json['MonthsOfYear'],
        'ordinal': !(0, runtime_1.exists)(json, 'Ordinal') ? undefined : json['Ordinal'],
        'endOn': !(0, runtime_1.exists)(json, 'EndOn') ? undefined : json['EndOn'],
        'endOnOccurences': !(0, runtime_1.exists)(json, 'EndOnOccurences') ? undefined : json['EndOnOccurences'],
        'dayOfMonth': !(0, runtime_1.exists)(json, 'DayOfMonth') ? undefined : json['DayOfMonth'],
        'dayOfWeek': !(0, runtime_1.exists)(json, 'DayOfWeek') ? undefined : json['DayOfWeek'],
    };
}
exports.ScheduledScanRecurrenceApiModelFromJSONTyped = ScheduledScanRecurrenceApiModelFromJSONTyped;
function ScheduledScanRecurrenceApiModelToJSON(value) {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        'RepeatType': value.repeatType,
        'Interval': value.interval,
        'EndingType': value.endingType,
        'DaysOfWeek': value.daysOfWeek,
        'MonthsOfYear': value.monthsOfYear,
        'Ordinal': value.ordinal,
        'EndOn': value.endOn,
        'EndOnOccurences': value.endOnOccurences,
        'DayOfMonth': value.dayOfMonth,
        'DayOfWeek': value.dayOfWeek,
    };
}
exports.ScheduledScanRecurrenceApiModelToJSON = ScheduledScanRecurrenceApiModelToJSON;
//# sourceMappingURL=ScheduledScanRecurrenceApiModel.js.map