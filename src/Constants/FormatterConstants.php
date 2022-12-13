<?php


namespace Apadana\Auth_armj\Constants;



class FormatterConstants
{
    //formatter for js files
    const CALENDAR_DATE_FORMAT_VIEW = 'yy/mm/dd';

    //format of ldap dates. A "Z" char add to end of this attribute when it store to ldap. [ Do not add "Z" here ]
    const LDAP_DATE_FORMAT = 'YmdHis.0';
    //format of dates used in php files
    const VIEW_DATE_FORMAT = 'Y/m/d';

    const VIEW_DATE_TIME_FORMAT = 'Y/m/d H:i:s';

    const DB_DATE_FORMAT = 'Y-m-d H:i:s';
    const DB_TIME_FORMAT = 'H:i:s';
    const DB_DATE_FORMAT_FAX = 'Y-m-dTH:i:s.000000Z'; //2020-11-24T07:10:42.000000Z

}
