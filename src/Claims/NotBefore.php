<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) 2014-2021 Sean Tymon <tymon148@gmail.com>
 * (c) 2021 PHP Open Source Saver
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Apadana\Auth_armj\Claims;

use Apadana\Auth_armj\Exceptions\TokenInvalidException;

class NotBefore extends Claim
{
    use DatetimeTrait;

    /**
     * {@inheritdoc}
     */
    protected $name = 'nbf';

    /**
     * {@inheritdoc}
     *
     * @throws TokenInvalidException
     */
    public function validatePayload()
    {
        if ($this->isFuture($this->getValue())) {
            throw new TokenInvalidException('Not Before (nbf) timestamp cannot be in the future');
        }
    }
}
