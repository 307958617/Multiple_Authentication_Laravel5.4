<?php

namespace App\Http\Controllers\Auth\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\ResetsPasswords;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Password;

class ResetPasswordController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Password Reset Controller
    |--------------------------------------------------------------------------
    |
    | This controller is responsible for handling password reset requests
    | and uses a simple trait to include this behavior. You're free to
    | explore this trait and override any methods you wish to tweak.
    |
    */

    use ResetsPasswords;

    /**
     * Where to redirect users after resetting their password.
     *
     * @var string
     */
    protected $redirectTo = '/admin'; //修改为admin

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest:admin');//添加admin guard
    }

    public function showResetForm(Request $request, $token = null)//重构ResetsPasswords里面的该方法
    {
        return view('auth.admin.passwords.reset')->with(   //将auth.passwords.reset改为auth.admin.passwords.reset
            ['token' => $token, 'email' => $request->email]
        );
    }

    public function broker() //重构ResetsPasswords里面的该方法
    {
        return Password::broker('admins');
    }

    protected function guard()//重构ResetsPasswords里面的该方法
    {
        return Auth::guard('admin');
    }
}
