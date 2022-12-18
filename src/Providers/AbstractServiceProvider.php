<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) 2014-2021 Sean armj <armj148@gmail.com>
 * (c) 2021 PHP Open Source Saver
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Apadana\Auth_armj\Providers;

use Apadana\Auth_armj\Blacklist;
use Apadana\Auth_armj\Claims\Factory as ClaimFactory;
use Apadana\Auth_armj\Console\JWTGenerateCertCommand;
use Apadana\Auth_armj\Console\JWTGenerateSecretCommand;
use Apadana\Auth_armj\Contracts\Providers\Auth;
use Apadana\Auth_armj\Contracts\Providers\JWT as JWTContract;
use Apadana\Auth_armj\Contracts\Providers\Storage;
use Apadana\Auth_armj\Factory;
use Apadana\Auth_armj\Http\Auth\LdapAuthProvider;
use Apadana\Auth_armj\Http\Middleware\Authenticate;
use Apadana\Auth_armj\Http\Middleware\AuthenticateAndRenew;
use Apadana\Auth_armj\Http\Middleware\Check;
use Apadana\Auth_armj\Http\Middleware\RefreshToken;
use Apadana\Auth_armj\Http\Parser\AuthHeaders;
use Apadana\Auth_armj\Http\Parser\InputSource;
use Apadana\Auth_armj\Http\Parser\Parser;
use Apadana\Auth_armj\Http\Parser\QueryString;
use Apadana\Auth_armj\JWT;
use Apadana\Auth_armj\JWTAuth;
use Apadana\Auth_armj\JWTGuard;
use Apadana\Auth_armj\Manager;
use Apadana\Auth_armj\Providers\JWT\Lcobucci;
use Apadana\Auth_armj\Providers\JWT\LdapServiceProvider;
use Apadana\Auth_armj\Providers\JWT\Namshi;
use Apadana\Auth_armj\Validators\PayloadValidator;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Namshi\JOSE\JWS;

abstract class AbstractServiceProvider extends ServiceProvider
{
    /**
     * The middleware aliases.
     */
    protected array $middlewareAliases = [
        'jwt.auth' => Authenticate::class,
        'jwt.check' => Check::class,
        'jwt.refresh' => RefreshToken::class,
        'jwt.renew' => AuthenticateAndRenew::class,
    ];

    /**
     * Boot the service provider.
     *
     * @return void
     */
    abstract public function boot();

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {

        $this->offerPublishing();
        $this->registerAliases();

        $this->registerJWTProvider();
        $this->registerAuthProvider();
        $this->registerStorageProvider();
        $this->registerJWTBlacklist();

        $this->registerManager();
        $this->registerTokenParser();

        $this->registerJWT();
        $this->registerJWTAuth();
        $this->registerPayloadValidator();
        $this->registerClaimFactory();
        $this->registerPayloadFactory();
        $this->registerJWTCommands();

        $this->commands([
            'armj.jwt.secret',
            'armj.jwt.cert',
        ]);
    }

    protected function offerPublishing()
    {
        if (! function_exists('config_path')) {
            // function not available and 'publish' not relevant in Lumen
            return;
        }

        $this->publishes([
            __DIR__.'/../../config/' => config_path(),
        ], 'config');

        $this->publishes([
            __DIR__.'/../../database/migrations/create_ldap_tables.php.stub' => $this->getMigrationFileName('create_ldap_tables.php'),
        ], 'migrations');
    }

    /**
     * Extend Laravel's Auth.
     *
     * @return void
     */
    protected function extendAuthGuard()
    {
        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            $guard = new JWTGuard(
                $app['armj.jwt'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request'],
                $app['events']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    /**
     * Bind some aliases.
     *
     * @return void
     */
    protected function registerAliases()
    {
        $this->app->alias('armj.jwt', JWT::class);
        $this->app->alias('armj.jwt.auth', JWTAuth::class);
        $this->app->alias('armj.jwt.provider.jwt', JWTContract::class);
        $this->app->alias('armj.jwt.provider.jwt.namshi', Namshi::class);
        $this->app->alias('armj.jwt.provider.jwt.lcobucci', Lcobucci::class);
        $this->app->alias('armj.jwt.provider.auth', Auth::class);
        $this->app->alias('armj.jwt.provider.storage', Storage::class);
        $this->app->alias('armj.jwt.manager', Manager::class);
        $this->app->alias('armj.jwt.blacklist', Blacklist::class);
        $this->app->alias('armj.jwt.payload.factory', Factory::class);
        $this->app->alias('armj.jwt.validators.payload', PayloadValidator::class);
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     *
     * @return void
     */
    protected function registerJWTProvider()
    {
        $this->registerNamshiProvider();
        $this->registerLcobucciProvider();

        $this->app->singleton('armj.jwt.provider.jwt', fn ($app) => $this->getConfigInstance($app, 'providers.jwt'));
    }

    /**
     * Register the bindings for the Namshi JWT provider.
     *
     * @return void
     */
    protected function registerNamshiProvider()
    {
        $this->app->singleton('armj.jwt.provider.jwt.namshi', fn ($app) => new Namshi(
            new JWS(['typ' => 'JWT', 'alg' => $app->make('config')->get('jwt.algo')]),
            $app->make('config')->get('jwt.secret'),
            $app->make('config')->get('jwt.algo'),
            $app->make('config')->get('jwt.keys')
        ));
    }

    /**
     * Register the bindings for the Lcobucci JWT provider.
     *
     * @return void
     */
    protected function registerLcobucciProvider()
    {
        $this->app->singleton('armj.jwt.provider.jwt.lcobucci', fn ($app) => new Lcobucci(
            $app->make('config')->get('jwt.secret'),
            $app->make('config')->get('jwt.algo'),
            $app->make('config')->get('jwt.keys')
        ));
    }
    public function provides()
    {
        return [
            'cache', 'cache.store', 'cache.psr6', 'memcached.connector',
        ];
    }

    /**
     * Register the bindings for the Auth provider.
     *
     * @return void
     */
    protected function registerAuthProvider()
    {
        $this->app->singleton('armj.jwt.provider.auth', fn ($app) => $this->getConfigInstance($app, 'providers.auth'));
    }

    /**
     * Register the bindings for the Storage provider.
     *
     * @return void
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('armj.jwt.provider.storage', fn ($app) => $this->getConfigInstance($app, 'providers.storage'));
    }

    /**
     * Register the bindings for the JWT Manager.
     *
     * @return void
     */
    protected function registerManager()
    {
        $this->app->singleton('armj.jwt.manager', function ($app) {
            $instance = new Manager(
                $app['armj.jwt.provider.jwt'],
                $app['armj.jwt.blacklist'],
                $app['armj.jwt.payload.factory']
            );

            return $instance->setBlacklistEnabled((bool) $app->make('config')->get('jwt.blacklist_enabled'))
                ->setPersistentClaims($app->make('config')->get('jwt.persistent_claims'))
                ->setBlackListExceptionEnabled((bool) $app->make('config')->get('jwt.show_black_list_exception', 0));
        });
    }

    /**
     * Register the bindings for the Token Parser.
     *
     * @return void
     */
    protected function registerTokenParser()
    {
        $this->app->singleton('armj.jwt.parser', function ($app) {
            $parser = new Parser(
                $app['request'],
                [
                    new AuthHeaders(),
                    new QueryString(),
                    new InputSource(),
                ]
            );

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });
    }

    /**
     * Register the bindings for the main JWT class.
     *
     * @return void
     */
    protected function registerJWT()
    {
        $this->app->singleton('armj.jwt', fn ($app) => (new JWT(
            $app['armj.jwt.manager'],
            $app['armj.jwt.parser']
        ))->lockSubject($app->make('config')->get('jwt.lock_subject')));
    }

    /**
     * Register the bindings for the main JWTAuth class.
     *
     * @return void
     */
    protected function registerJWTAuth()
    {
        $this->app->singleton('armj.jwt.auth', fn ($app) => (new JWTAuth(
            $app['armj.jwt.manager'],
            $app['armj.jwt.provider.auth'],
            $app['armj.jwt.parser']
        ))->lockSubject($app->make('config')->get('jwt.lock_subject')));
    }

    /**
     * Register the bindings for the Blacklist.
     *
     * @return void
     */
    protected function registerJWTBlacklist()
    {
        $this->app->singleton('armj.jwt.blacklist', function ($app) {
            $instance = new Blacklist($app['armj.jwt.provider.storage']);

            return $instance->setGracePeriod($app->make('config')->get('jwt.blacklist_grace_period'))
                            ->setRefreshTTL($app->make('config')->get('jwt.refresh_ttl'));
        });
    }

    /**
     * Register the bindings for the payload validator.
     *
     * @return void
     */
    protected function registerPayloadValidator()
    {
        $this->app->singleton('armj.jwt.validators.payload', fn ($app) => (new PayloadValidator())
            ->setRefreshTTL($app->make('config')->get('jwt.refresh_ttl'))
            ->setRequiredClaims($app->make('config')->get('jwt.required_claims')));
    }

    /**
     * Register the bindings for the Claim Factory.
     *
     * @return void
     */
    protected function registerClaimFactory()
    {
        $this->app->singleton('armj.jwt.claim.factory', function ($app) {
            $factory = new ClaimFactory($app['request']);
            $app->refresh('request', $factory, 'setRequest');

            return $factory->setTTL($app->make('config')->get('jwt.ttl'))
                           ->setLeeway($app->make('config')->get('jwt.leeway'));
        });
    }

    /**
     * Register the bindings for the Payload Factory.
     *
     * @return void
     */
    protected function registerPayloadFactory()
    {
        $this->app->singleton('armj.jwt.payload.factory', fn ($app) => new Factory(
            $app['armj.jwt.claim.factory'],
            $app['armj.jwt.validators.payload']
        ));
    }

    /**
     * Register the Artisan command.
     *
     * @return void
     */
    protected function registerJWTCommands()
    {
        $this->app->singleton('armj.jwt.secret', fn () => new JWTGenerateSecretCommand());
        $this->app->singleton('armj.jwt.cert', fn () => new JWTGenerateCertCommand());
    }

    /**
     * Get an instantiable configuration instance.
     *
     * @param Application $app
     * @param string      $key
     *
     * @return mixed
     */
    protected function getConfigInstance($app, $key)
    {
        $instance = $app->make('config')->get('jwt.'.$key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
