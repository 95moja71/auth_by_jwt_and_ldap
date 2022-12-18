<?php

/**
 * Created by Reliese Model.
 */

namespace Apadana\Auth_armj\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * Class LdapServer
 *
 * @property int $id_ldap_server
 * @property string $name
 * @property int $port
 * @property string $admin_dn
 * @property string $admin_pw
 * @property string $search_filter
 * @property string $search_base
 * @property int $enable
 * @property int $active
 *
 * @package App\Models
 */
class LdapServer extends Model
{
	protected $table = 'ldap_servers';

	protected $casts = [
		'port' => 'int',
		'enable' => 'int',
		'active' => 'int'
	];

	protected $fillable = [
		'name',
		'port',
		'admin_dn',
		'admin_pw',
		'search_filter',
		'search_base',
		'enable',
		'active'
	];
}
