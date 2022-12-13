<?php


namespace Apadana\Auth_armj\Ldap\Authentication;


use Apadana\Auth_armj\jwt\JwtService;
use Apadana\Auth_armj\Ldap\Constants\SelfServiceConstants;
use Apadana\Auth_armj\Ldap\Service\DataService;
use Apadana\Auth_armj\Logger\ApadanaLogger;

/**
 * Class UsersAuthenticationHandler
 * @package App\Apadana\AD\Authentication
 * This class is for authenticating users to active directory
 */
class UsersAuthenticationHandler
{
    /**
     * @param $username
     * @param $password
     * @return array|null
     * authenticate user in ldap
     */
    public function authenticate($username, $password)
    {
        try {
            $bind_res = ApadanaLdap::Bind($username, $password);
            if ($bind_res['bind'] != false) {
                ApadanaLogger::info(SelfServiceConstants::LDAP_USERNAME_ATTRIBUTE . "=" . $username . " bind successfully");
                $ldap = $bind_res['ldap'];
                $data_service = new DataService();
                $info = $data_service->loadUsersAttributes($username, $ldap);
                ApadanaLdap::closeConnection($ldap);
                $info['auth'] = true;
                return $info;
            }

            ApadanaLogger::info(SelfServiceConstants::LDAP_USERNAME_ATTRIBUTE . "=" . $username . " can not bind");
            $info['auth'] = false;
            $info['error_no'] = $bind_res['error_no'];

            return $info;
        } catch (\Exception $e) {
            ApadanaLogger::info("Exception on authenticating: " . $e->getMessage());
            ApadanaLogger::debug("Exception on authenticating: " . $e->getTraceAsString());
            return null;
        }

    }




}
