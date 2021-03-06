<?php
/**
 * @package     Plugin
 * @subpackage  Authentication.Admidio
 *
 * @copyright   Copyright (C) 2020 Thomas Hunziker. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

use Joomla\CMS\Authentication\Authentication;
use Joomla\CMS\Authentication\AuthenticationResponse;
use Joomla\CMS\Language\Text;
use Joomla\CMS\User\User;
use Joomla\CMS\User\UserHelper;

/**
 * Admidio Authentication plugin
 *
 * @since  1.0
 */
class PlgAuthenticationAdmidio extends JPlugin
{
	/**
	 * This method should handle any authentication and report back to the subject
	 *
	 * @param array    $credentials Array holding the user credentials
	 * @param array    $options     Array of extra options
	 * @param object  &$response    Authentication response object
	 *
	 * @return  void
	 *
	 * @since   1.0
	 */
	public function onUserAuthenticate($credentials, $options, &$response)
	{
		$response->type = 'Admidio';

		// Joomla does not like blank passwords
		if (empty($credentials['password']))
		{
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');

			return;
		}

		// Get a database object
		$dboptions = array(
			'driver'   => 'mysql',
			'host'     => 'localhost',
			'user'     => $this->params->get('user'),
			'password' => $this->params->get('password'),
			'database' => $this->params->get('database'),
			'prefix'   => 'adm_',
		);

		$db    = JDatabaseDriver::getInstance($dboptions);
		$query = $db->getQuery(true)
			->select('usr_id, usr_password')
			->from('#__users')
			->where('`usr_login_name` = ' . $db->quote($credentials['username']));

		$db->setQuery($query);
		$result = $db->loadObject();

		if ($result)
		{
			$match = password_verify($credentials['password'], $result->usr_password);

			if ($match === true)
			{
				$query = $db->getQuery(true)
					->select('usd_usf_id, usd_value')
					->from('#__user_data')
					->where('`usd_usr_id` = ' . $result->usr_id);

				$db->setQuery($query);
				$userData = $db->loadObjectList('usd_usf_id');

				// Joomla benötigt eine Emailadresse!
				if (empty($userData[12]->usd_value))
				{
					$response->status        = Authentication::STATUS_FAILURE;
					$response->error_message = 'Bitte in der Adressverwaltung bei deinem Benutzer eine Emailadresse angeben.';

					return;
				}

				$response->email    = $userData[12]->usd_value;
				$response->fullname = $userData[2]->usd_value . ' ' . $userData[1]->usd_value;

				$response->status        = Authentication::STATUS_SUCCESS;
				$response->error_message = '';

				$this->createUser($credentials, $response);
			}
			else
			{
				// Invalid password
				$response->status        = Authentication::STATUS_FAILURE;
				$response->error_message = Text::_('JGLOBAL_AUTH_INVALID_PASS');
			}
		}
		else
		{
			// Let's hash the entered password even if we don't have a matching user for some extra response time
			// By doing so, we mitigate side channel user enumeration attacks
			password_hash($credentials['password'], PASSWORD_DEFAULT);

			// Invalid user
			$response->status        = Authentication::STATUS_FAILURE;
			$response->error_message = Text::_('JGLOBAL_AUTH_NO_USER');
		}
	}

	/**
	 * Create the user if it doesn't exist yet or update the groups
	 *
	 * @param array                  $credentials
	 * @param AuthenticationResponse $user Holds the user data
	 *
	 * @return  boolean  True on success
	 *
	 * @since   1.0
	 */
	private function createUser($credentials, $user)
	{
		$id       = (int) UserHelper::getUserId($credentials['username']);
		$instance = User::getInstance($id);

		// Create User if it doesn't exist.
		if (!$id)
		{
			$instance->name           = $user->fullname;
			$instance->username       = $credentials['username'];
			$instance->password_clear = $credentials['password'];
			$instance->email          = $user->email;
		}

		// Get a database object
		$dboptions = array(
			'driver'   => 'mysql',
			'host'     => 'localhost',
			'user'     => $this->params->get('user'),
			'password' => $this->params->get('password'),
			'database' => $this->params->get('database'),
			'prefix'   => 'adm_',
		);

		$db    = JDatabaseDriver::getInstance($dboptions);
		$query = $db->getQuery(true)
			->select('rol_name')
			->from('#__members')
			->join('INNER', '`#__roles` ON `mem_rol_id` = `rol_id`')
			->join('INNER', '`#__users` ON `mem_usr_id` = `usr_id`')
			->where('`usr_login_name` = "' . $credentials['username'] . '"');

		$db->setQuery($query);
		$groupsAdmidio = $db->loadColumn();

		// Get the user groups from the database.
		$db    = JFactory::getDbo();
		$query = $db->getQuery(true)
			->select('id')
			->from('#__usergroups')
			->where('`title` IN ("' . implode('","', $groupsAdmidio) . '")');

		$db->setQuery($query);

		$instance->groups = $db->loadColumn();

		if (!$instance->save())
		{
			JLog::add('Error in autoregistration for user ' . $credentials['username'] . '.', JLog::WARNING, 'error');

			return false;
		}

		return true;
	}
}
