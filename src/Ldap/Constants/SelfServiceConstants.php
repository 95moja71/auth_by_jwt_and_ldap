<?php


namespace Apadana\Auth_armj\Ldap\Constants;


class SelfServiceConstants
{
    const LDAP_USERNAME_ATTRIBUTE = "samaccountname";
    const LDAP_DN_ATTRIBUTE = "distinguishedname";
    const MOBILE_VERIFICATION_FIELD = "mobile_is_verified";

    const METHOD_SMS = 'sms';
    const METHOD_MAIL = 'mail';
    const RESET_CODE_LENGTH = 6;
    const PASSWORD_COMPLEXITY = "required|string|min:8|confirmed|regex:/^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{6,}$/";
    const NATIONAL_CODE_MAX_LENGTH = "10";
    const NATIONAL_CODE_MIN_LENGTH = "10";

    const CODE_EXPIRATION_TIME = 240; // in seconds
    const SERVER_TYPE = "AD"; // AD, OPENLDAP

    const BannerAttributes = ['personcode', 'samaccountname', 'whenchanged', 'whencreated', 'givenname', 'sn', 'company', 'department', 'title', 'thumbnailphoto'];
}
