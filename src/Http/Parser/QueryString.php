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

namespace Apadana\Auth_armj\Http\Parser;

use Illuminate\Http\Request;
use Apadana\Auth_armj\Contracts\Http\Parser as ParserContract;

class QueryString implements ParserContract
{
    use KeyTrait;

    /**
     * Try to parse the token from the request query string.
     *
     * @return string|null
     */
    public function parse(Request $request)
    {
        return $request->query($this->key);
    }
}
