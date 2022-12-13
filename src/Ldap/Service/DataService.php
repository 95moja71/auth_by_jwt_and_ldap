<?php


namespace Apadana\Auth_armj\Ldap\Service;

use Apadana\Auth_armj\Ldap\Authentication\ApadanaLdap;
use Apadana\Auth_armj\Logger\ApadanaLogger;
use Apadana\Auth_armj\Constants\UserMgtConstants;
use App\AD\Service\SystemAttribute;
use App\Models\LdapAttribute;
use DB;

/**
 * Class ADService
 * @package App\Apadana\AD\Service
 * This class is for interacting with ldap after authenticating user
 */
class DataService
{
    /**
     * @param $username
     * @return array|null
     */
    public function loadUsersAttributes($username, $ldap)
    {
        $user_info = ApadanaLdap::SearchByUsername($username, $ldap);

        if ($user_info['count'] == 1) {
            return $user_info;
        }
        return null;
    }

    /**
     * @param $username
     * @param array $attributes
     */
    public function updateUsersAttributes($username, array $attributes)
    {

        $dn = ApadanaLdap::getObjectRDN($username);
        //ldap_set_option($ad, LDAP_OPT_PROTOCOL_VERSION, 3);

        $bind = ApadanaLdap::AdminBind();
        if ($bind != null) {
            $admin_connection = $bind['ldap'];

            try {
                foreach ($attributes as $index => $attribute) {
                    if ($attribute == null) {
                        unset($attributes[$index]);
                    }
                }

                $result = ldap_mod_replace($admin_connection, $dn, $attributes);
            } catch (\Exception $e) {
                ApadanaLogger::info("Exception on modify attributes in ldap :" . $e->getMessage());

                return null;
            }
            $this->loadUsersAttributes($username, $admin_connection);

            ApadanaLdap::closeConnection($admin_connection);

            ApadanaLogger::info("update user attributes done");
            return $result;
        }

        return null;
    }

    /**
     * @return mixed
     */
    public function loadProfileFormAttributes()
    {
        $query = "SELECT
                    ldap_attributes.id_ldap_attribute,
                    ldap_attributes.name,
                    ldap_attributes.description as description,
                    data_types.id_data_type,
                    data_types.data_type_name,
                    data_types.data_type_code,
                    system_attributes.id_system_attribute,
                    system_attributes.system_attribute_name,
                    system_attributes.is_enable,
                    system_attributes.is_editable,
                    system_attributes.view_order
                    FROM ldap_attributes
                    join data_types on data_types.id_data_type = ldap_attributes.id_data_type
                    join system_attributes on system_attributes.id_ldap_attribute = ldap_attributes.id_ldap_attribute
                    where active = '1'
                    and data_types.data_type_active='1'
                    and system_attributes.system_attribute_active = '1'
                    and system_attributes.is_enable = '1'
                    order by view_order";

        return DB::select($query);
    }

    /**
     * @return mixed
     */
    public function loadBannerAttributes()
    {
        $query = "SELECT
                    ldap_attributes.id_ldap_attribute,
                    ldap_attributes.name,
                    ldap_attributes.description as description,
                    data_types.id_data_type,
                    data_types.data_type_name,
                    data_types.data_type_code,
                    system_attributes.id_system_attribute,
                    system_attributes.system_attribute_name,
                    system_attributes.is_enable,
                    system_attributes.is_editable,
                    system_attributes.view_order
                    FROM ldap_attributes
                    join data_types on data_types.id_data_type = ldap_attributes.id_data_type
                    join system_attributes on system_attributes.id_ldap_attribute = ldap_attributes.id_ldap_attribute
                    where active = '1'
                    and data_types.data_type_active='1'
                    and system_attributes.system_attribute_active = '1'
                    and ldap_attributes.name in ('" . implode("','", SelfServiceConstants::BannerAttributes) . "')
                    order by view_order";

        return DB::select($query);
    }

    /**
     * @return mixed
     */
    public function loadProfileAttributeValidationRules()
    {
        $query = "select
                        validation_rules.id_validation_rule,
                        validation_rules.validation_rule_name,
                        validation_rules.validation_rule_value,
                        system_attributes.id_system_attribute,
                        system_attributes.system_attribute_name,
                        system_attributes.system_attribute_code,
                        system_attributes.is_editable,
                        system_attributes.is_enable
                        from validation_rules
                        join attribute_validations
                        on attribute_validations.id_validation_rule = validation_rules.id_validation_rule
                        join system_attributes on system_attributes.id_system_attribute = attribute_validations.id_system_attribute
                        where validation_rules.validation_rule_active = '1'
                        and system_attributes.system_attribute_active = '1'
                        and attribute_validations.attribute_validation_active = '1'";

        return DB::select($query);
    }


    /**
     * @param $ldap_entry
     * @param null $username
     */
    private function setAuthenticatedUser($ldap_entry, $username = null)
    {
        $allowed_attributes = LdapAttribute::where('active', '=', '1')->get();

        $user = [];


        foreach ($allowed_attributes as $allowed_attribute) {
            $system_attrs = SystemAttribute::where('id_ldap_attribute', '=', $allowed_attribute->id_ldap_attribute)
                ->where('system_attribute_active', '=', '1')
                ->get();
            foreach ($system_attrs as $system_attr) {
                $user[$system_attr->system_attribute_name] = [];

                if (array_key_exists(strtolower($allowed_attribute->name), $ldap_entry)
                    and $ldap_entry[strtolower($allowed_attribute->name)]['count'] > 0) {
                    foreach ($ldap_entry[strtolower($allowed_attribute->name)] as $key => $attr_value) {
                        if ($key === 'count')
                            continue;

                        $user[$system_attr->system_attribute_name][] = $attr_value;
                        if ($system_attr->system_attribute_name == 'avatar') {
                            $user[$system_attr->system_attribute_name][] = pack('C*', $attr_value);
                        }
                    }
                }
            }
        }
        if (array_key_exists('avatar', $user) and sizeof($user['avatar']) > 0) {
            $user['avatar'][0] = base64_encode($user['avatar'][0]);
        }
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        $_SESSION['username'] = $username;
        $_SESSION['profile'] = $user;
        try {
            $ldap_groups = $ldap_entry['memberof'];
            unset($ldap_groups['count']);
            $_SESSION['memberof'] = $ldap_groups;
            if (!in_array(strtolower(config('apadana.applications.profile.parnian_group_name')), array_map('strtolower', $_SESSION['memberof']))) {
                unset($_SESSION['user']['distribution_code']);
            }
        } catch (\Exception $e) {
            ApadanaLogger::info("Exception on access memberof attribute for user " . $username);
        }

    }

    /**
     * @param $login_name
     * @return array|null
     */
    public function loadUserAttributesByLoginName($login_name)
    {
        $ldap_connection = ApadanaLdap::getConnection();
        $bind = ApadanaLdap::AdminBind();
        if ($bind['bind']) {
            $ldap_connection = $bind['ldap'];
            $user_info = ApadanaLdap::SearchByLoginName($login_name, $ldap_connection);

            if ($user_info['count'] == 1) {
                ApadanaLogger::debug("User info returned");
                return $user_info[0];
            } else if ($user_info['count'] > 1) {
                ApadanaLogger::error("More than one entry found for login_name " . $login_name);
                foreach ($user_info as $index => $user) {
                    if ($index === 'count') {
                        continue;
                    }
                    ApadanaLogger::debug("List of entries return by login_name : dn=" . $user['distinguishedname'][0]);
                }
            } else
                ApadanaLogger::error("No entry found for login_name " . $login_name);

        }

        return null;
    }

    /**
     * @param $dn
     * @return array|null
     * This method is to pass user attributes to other services
     */
    public function loadUserAttributesByDN($dn)
    {
        $bind = ApadanaLdap::AdminBind();

        if ($bind['bind']) {
            $ldap_connection = $bind['ldap'];
            $user_info = ApadanaLdap::SearchByDN($dn, $ldap_connection);

            if ($user_info['count'] == 1) {
                ApadanaLogger::debug("User info returned");
                return $user_info[0];
            } else if ($user_info['count'] > 1) {
                ApadanaLogger::error("More than one entry found for dn " . $dn);
                foreach ($user_info as $index => $user) {
                    if ($index === 'count') {
                        continue;
                    }
                    ApadanaLogger::debug("List of entries return by login_name : dn=" . $user['distinguishedname'][0]);
                }
            } else
                ApadanaLogger::error("No entry found for login_name " . $dn);

        }

        return null;
    }

    /**
     * @param $dn
     * @return array|null
     * This method is to pass user attributes to other services
     */
    public function loadAllUsersAttributes($search_filter)
    {
        $bind = ApadanaLdap::AdminBind();

        if ($bind['bind']) {
            $ldap_connection = $bind['ldap'];
            $users = ApadanaLdap::Search($search_filter, $ldap_connection);

            if ($users != null and $users['count'] >= 1) {
                ApadanaLogger::debug("User info returned");
                return $users;
            } else
                ApadanaLogger::error("No entry found for $search_filter ");

        }

        return null;
    }

    public function convertLdapArrayToLaravelModel($user)
    {

        $array = [];
        $fields = config('ldap.fields');
        foreach ($fields as $key => $field) {
            $array[$key] = (isset($user[$field]) and sizeof($user[$field])) > 0 ? $user[$field][0] : null;

        }
        $array['object_guid']=bin2hex($user[UserMgtConstants::LDAPGUID][0]);
        $array['username'] = (isset($user[UserMgtConstants::USERNAME]) and sizeof($user[UserMgtConstants::USERNAME])) > 0 ? $user[UserMgtConstants::USERNAME][0] : null;

        return $array;
    }


}
