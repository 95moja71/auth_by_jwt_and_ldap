<?php


namespace Apadana\Auth_armj\Constants;


class UserMgtConstants
{
    const USERNAME                      = 'samaccountname';
    const USERNAME_ALTERNATE            = 'sAMAccountName';
    const LDAPGUID                          = 'objectguid';
    const GUID                          = 'object_guid';

    /**
     * Control options for disable/enable users to use in `userAccountControl`
     */
    const USER_ENABLE                   = 544;
    const USER_DISABLE                  = 546;


}
