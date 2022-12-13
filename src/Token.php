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

namespace Apadana\Auth_armj;

use Apadana\Auth_armj\Validators\TokenValidator;

class Token
{
    private string $value;

    /**
     * Create a new JSON Web Token.
     *
     * @param string $value
     *
     * @return void
     *
     * @throws Exceptions\TokenInvalidException
     */
    public function __construct($value)
    {
        $this->value = (string) (new TokenValidator())->check($value);
    }

    /**
     * Get the token.
     *
     * @return string
     */
    public function get()
    {
        return $this->value;
    }

    /**
     * Get the token when casting to string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->get();
    }
}
