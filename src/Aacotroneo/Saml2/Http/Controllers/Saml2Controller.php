<?php

namespace Aacotroneo\Saml2\Http\Controllers;

use Aacotroneo\Saml2\Events\Saml2LoginEvent;
use Aacotroneo\Saml2\Saml2Auth;
use Illuminate\Routing\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use OneLogin\Saml2\Auth as OneLogin_Saml2_Auth;
use URL;

class Saml2Controller extends Controller
{

    protected $saml2Auth;

    protected $idp;

    /**
     */
    function __construct(){
        $idpName = config('saml2_settings.idpNames')[0];
         if (app()->runningInConsole()) {
             $idpName = config('saml2_settings.idpNames')[0];
        }

        $this->idp = $idpName;
        $auth = Saml2Auth::loadOneLoginAuthFromIpdConfig($this->idp);
        $this->saml2Auth = new Saml2Auth($auth);
    }

    /**
     * Generate local sp metadata
     * @return \Illuminate\Http\Response
     */
    public function metadata()
    {

        $metadata = $this->saml2Auth->getMetadata();

        return response($metadata, 200, ['Content-Type' => 'text/xml']);
    }

    /**
     * Process an incoming saml2 assertion request.
     * Fires 'Saml2LoginEvent' event if a valid user is Found
     */
    public function acs()
    {
        $errors = $this->saml2Auth->acs();

        if (!empty($errors)) {
            logger()->error('Saml2 error_detail', ['error' => $this->saml2Auth->getLastErrorReason()]);
            session()->flash('saml2_error_detail', [$this->saml2Auth->getLastErrorReason()]);

            logger()->error('Saml2 error', $errors);
            session()->flash('saml2_error', $errors);
            return redirect(config('saml2_settings.errorRoute'));
        }
        $user = $this->saml2Auth->getSaml2User();

        event(new Saml2LoginEvent($this->idp, $user, $this->saml2Auth));

        if (Session::has('flash_notification')) {
            return redirect(config('saml2_settings.errorRoute'));
        }

        $redirectUrl = $user->getIntendedUrl();

        if ($redirectUrl !== null) {
            return redirect($redirectUrl);
        } else {

            return redirect(config('saml2_settings.loginRoute'));
        }
    }

    /**
     * Process an incoming saml2 logout request.
     * Fires 'Saml2LogoutEvent' event if its valid.
     * This means the user logged out of the SSO infrastructure, you 'should' log him out locally too.
     */
    public function sls()
    {
        $errors = $this->saml2Auth->sls($this->idp, config('saml2_settings.retrieveParametersFromServer'));
        if (!empty($errors)) {
            $count = 0;
            $flashError = '';
            foreach ($errors as $err){
                $flashError = $count == 0 ? 'SSO: Logout ' . $err : $flashError . '</br>' . $err;
                $count ++;
            }
            flash()->error($flashError)->important();
            return redirect(config('saml2_settings.errorRoute'));
        }

        return redirect(config('saml2_settings.logoutRoute')); //may be set a configurable default
    }

    /**
     * This initiates a logout request across all the SSO infrastructure.
     */
    public function logout(Request $request, $sessionIndex)
    {
        $returnTo = $request->query('returnTo');
        //$sessionIndex = $request->query('sessionIndex');
        $nameId = $request->query('nameId');
        $this->saml2Auth->logout($returnTo, $nameId, $sessionIndex); //will actually end up in the sls endpoint
        //does not return
    }


    /**
     * This initiates a login request
     */
    public function login()
    {
        $this->saml2Auth->login(config('saml2_settings.loginRoute'));
    }
}
