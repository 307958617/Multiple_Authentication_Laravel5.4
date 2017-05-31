<?php

namespace App\Http\Controllers\Auth\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/admin';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest:admin')->except('logout');
    }

    public function showLoginForm()
    {
        return view('auth.admin.login');
    }

    public function login(Request $request)
    {
        //实现登录数据的验证功能
        $this->validate($request,[
            'email' => 'required|email',
            'password' => 'required|min:6'
        ]);
        //判断登录是否成功
        if(Auth::guard('admin')->attempt(['email'=>$request->email,'password'=>$request->password],$request->has('remember'))){
            //如果成功跳转到 注意！这里需要用到admin guard来指定是admin用户的登录，而不是默认user登录。
            //attempt()方法里面就是用户名和密码的验证条件，满足了才表示成功登录了
            //这里还有一个隐藏知识点，就是TrimString这个middleware，密码不可以有空格，不去到空格。
            return redirect()->intended(route('admin.dashboard'));
        }
        //如果失败，那么就返回登录界面，并且携带填写的数据回去。
        return back()->withInput($request->only('email','remember'));
    }

    public function logout()
    {
        Auth::guard('admin')->logout();
        return redirect('/');
    }
}

