<?php

namespace Apadana\Auth_armj\Providers\Auth;

use Apadana\Auth_armj\Http\Auth\LdapAuthProvider;
use Illuminate\Support\ServiceProvider;

class LdapServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        $this->app['auth']->provider('ldap', function () {
            return new LdapAuthProvider(config('auth.providers.users.model'));
        });
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }
}
