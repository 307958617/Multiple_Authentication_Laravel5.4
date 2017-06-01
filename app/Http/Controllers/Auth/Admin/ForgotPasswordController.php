<?php

namespace App\Http\Controllers\Auth\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\SendsPasswordResetEmails;
use Illuminate\Support\Facades\Password;

class ForgotPasswordController extends Controller
{
    use SendsPasswordResetEmails;

    public function __construct()
    {
        $this->middleware('guest:admin');//修改为必须是admin用户
    }

    public function showLinkRequestForm() //重构SendsPasswordResetEmails里面的该方法
    {
        return view('auth.admin.passwords.email'); //修改为admin用户存放重置密码视图文件
    }

    public function broker() //重构SendsPasswordResetEmails里面的该方法
    {
        return Password::broker('admins');//这里对应的是config->auth.app里面配置的passwords的admins，表示使用的是admin用户
    }
}
