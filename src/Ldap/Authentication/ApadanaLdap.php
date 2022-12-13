<?php


namespace Apadana\Auth_armj\Ldap\Authentication;

use Apadana\Auth_armj\Ldap\Constants\SelfServiceConstants;
use Apadana\Auth_armj\Ldap\Service\DataService;
use Apadana\Auth_armj\Logger\ApadanaLogger;
use App\Models\LdapServer;

class ApadanaLdap
{
    /**
     * @return bool|false|resource|null
     */
    public static function getConnection()
    {
        try {
            $ldap_server = LdapServer::where('active', '1')
                ->where('enable', '1')
                ->first();
            if ($ldap_server == null) {
                ApadanaLogger::info("No valid ldapserver configuration found ");
                return false;
            }

            $adServer = $ldap_server->name . ":" . $ldap_server->port;
            $ldap = @ldap_connect($adServer);

            return $ldap;
        } catch (\Exception $e) {
            ApadanaLogger::info("Exception on connecting to ldap : " . $e->getMessage());
            ApadanaLogger::debug("Exception on connecting to ldap : " . $e->getTraceAsString());
            return null;
        }
    }

    /**
     * @param $username
     * @return bool|string|string[]
     */
    public static function getObjectRDN($username)
    {
        $data_service = new DataService();
        $user = $data_service->loadUserAttributesByLoginName($username);
        return $user != null ? $user['' . SelfServiceConstants::LDAP_DN_ATTRIBUTE . ''][0] : null;
    }


    /**
     * @param $username
     * @param $password
     * @return array|null
     */
    public static function Bind($username, $password)
    {
        try {
            $ldap = ApadanaLdap::getConnection();
            $ldaprdn = ApadanaLdap::getObjectRDN($username);

            putenv('LDAPTLS_CIPHER_SUITE=NORMAL:!VERS-TLS1.2');
            ldap_set_option($ldap, LDAP_OPT_DEBUG_LEVEL, 7);
            ldap_set_option($ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, 0);
            ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

            $bind = @ldap_bind($ldap, $ldaprdn, $password);

            return $bind ? ['bind' => $bind, 'ldap' => $ldap] :
                ['bind' => false, 'error_no' => ldap_errno($ldap)];


        } catch (\Exception $e) {
            ApadanaLogger::info("Exception on bind to ldap : " . $e->getMessage());
            ApadanaLogger::debug("LDAP-Errno: " . ldap_err2str(ldap_errno($ldap)));
            return ['bind' => false, 'error_no' => ldap_errno($ldap)];
        }
    }

    /**
     * @return array|null
     */
    public static function AdminBind()
    {
        try {
            $data = LdapServer::where('active', '=', '1')
                ->where('enable', '1')
                ->first();
            if ($data == null) {
                ApadanaLogger::debug("No valid ldap server configuration found. Finding ldap server configuration that be valid and active in database failed.");
                return null;
            }
            $dn = $data->admin_dn;
            $pw = $data->admin_pw;
            $ldap = ApadanaLdap::getConnection();

            ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
            ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);

            $bind = @ldap_bind($ldap, $dn, $pw);

            return ['bind' => $bind, 'ldap' => $ldap];

        } catch (\Exception $e) {
            ApadanaLogger::info("Exception on bind to ldap : " . $e->getMessage());
//            ApadanaLogger::debug("LDAP-Errno: " . ldap_err2str(ldap_errno($ldap)));
            return null;
        }

    }

    /**
     * @param $connection
     */
    public static function closeConnection($connection)
    {
        try {
            @ldap_close($connection);
        } catch (\Exception $e) {
            ApadanaLogger::info("Exception on close ldap connection " . $e->getMessage());
        }
    }

    /**
     * @param $username
     * @param $connection
     * @return array|null
     */
    public static function SearchByUsername($username, $connection)
    {
        $ldap_server = LdapServer::where('active', '1')
            ->where('enable', '1')
            ->first();
        if ($ldap_server != null) {
            $search_base = $ldap_server->search_base;
            try {
                $filter = "(" . SelfServiceConstants::LDAP_USERNAME_ATTRIBUTE . "=$username)";
                ApadanaLogger::info("Search for entry " . $filter);
                ldap_set_option($connection, LDAP_OPT_DEBUG_LEVEL, 7);
                ldap_set_option($connection, LDAP_OPT_X_TLS_REQUIRE_CERT, 0);
                ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
                $result = @ldap_search($connection, $search_base, $filter);
                $info = @ldap_get_entries($connection, $result);

                return $info;
            } catch (\Exception $e) {
                ApadanaLogger::info("Excetion on search on ldap " . $e->getMessage());
                return null;
            }
        }
        ApadanaLogger::error("Error on load ldap configuration from database");

        return null;


    }

    /**
     * @param $username
     * @param $connection
     * @return array|null
     */
    public static function SearchByLoginName($login_name, $connection)
    {
        $ldap_server = LdapServer::where('active', '1')
            ->where('enable', '1')
            ->first();
        if ($ldap_server != null) {
            $search_filter = $ldap_server->search_filter;
            $search_base = $ldap_server->search_base;
            try {
                $search_filter = str_replace("%user%", $login_name, $search_filter);

                ApadanaLogger::debug("Search for entry by login_name using search filter " . $search_filter);
                ldap_set_option($connection, LDAP_OPT_DEBUG_LEVEL, 7);
                ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
                ldap_set_option($connection, LDAP_OPT_X_TLS_REQUIRE_CERT, 0);
                ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
                $result = ldap_search($connection, $search_base, $search_filter);
                $info = ldap_get_entries($connection, $result);
                return $info;
            } catch (\Exception $e) {
                ApadanaLogger::info("Excetion on search on ldap " . $e->getMessage());
                ApadanaLogger::debug("Excetion on search on ldap " . $e->getTraceAsString());
                return null;
            }
        }
        ApadanaLogger::error("Error on load ldap configuration from database");
        return null;

    }

    public static function SearchByDN($dn, $connection)
    {
        $ldap_server = LdapServer::where('active', '1')
            ->where('enable', '1')
            ->first();
        if ($ldap_server != null) {
            $search_base = $ldap_server->search_base;
            try {
                $search_filter = "(distinguishedName=" . $dn . ")";

                ApadanaLogger::debug("Search for entry by dn using search filter " . $search_filter);
                ldap_set_option($connection, LDAP_OPT_DEBUG_LEVEL, 7);
                ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
                ldap_set_option($connection, LDAP_OPT_X_TLS_REQUIRE_CERT, 0);
                ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
                $result = ldap_search($connection, $search_base, $search_filter);
                $info = ldap_get_entries($connection, $result);
                return $info;
            } catch (\Exception $e) {
                ApadanaLogger::info("Excetion on search on ldap " . $e->getMessage());
                ApadanaLogger::debug("Excetion on search on ldap " . $e->getTraceAsString());
                return null;
            }
        }
        ApadanaLogger::error("Error on load ldap configuration from database");
        return null;
    }

    /**
     * @param array $search_filter
     * @param $connection
     * @return array|null
     */
    public static function Search($search_filter, $connection)
    {
        $ldap_server = LdapServer::where('active', '1')
            ->where('enable', '1')
            ->first();
        if ($ldap_server != null) {
            $search_base = $ldap_server->search_base;
            try {
                ApadanaLogger::debug("Search for entries using search filter " . $search_filter);
                ldap_set_option($connection, LDAP_OPT_DEBUG_LEVEL, 7);
                ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
                ldap_set_option($connection, LDAP_OPT_X_TLS_REQUIRE_CERT, 0);
                ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
                $result = ldap_search($connection, $search_base, $search_filter);
                $info = ldap_get_entries($connection, $result);
                return $info;
            } catch (\Exception $e) {
                ApadanaLogger::info("Excetion on search on ldap " . $e->getMessage());
                ApadanaLogger::debug("Excetion on search on ldap " . $e->getTraceAsString());
                return null;
            }
        }
        ApadanaLogger::error("Error on load ldap configuration from database");
        return null;
    }

}
