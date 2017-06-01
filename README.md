# Multiple_Authentication_Laravel5.4（多用户认证的实现）
## 目标：laravel自带用户认证命令（phpartisan make auth）创建（users）用户认证，那么这里讲的就是在此基础上，再创建就一个（admins）管理员认证。这两个认证系统同时存在互不干扰
## 步骤一：实现laravel自带用户认证。
### 一、执行如下命令：（也只需要这一步就可以生成认证所有的东西）
    php artisan make:auth
## 步骤二：创建就一个（admins）管理员认证。
### 一、由于laravel自带的migration文件只有两个，一个是users，一个是password_resets。所以这一步就是需要为新的（admin）管理员用户创建一个migration文件（即表），用于存放管理员信息。
    php artisan make:migration create_admins_table --create=admins
### 二、编辑上面创建的create_admins_table文件（可以复制create_users_table，两个表可以一样）：
    public function up()
        {
            Schema::create('admins', function (Blueprint $table) {
                $table->increments('id');
                $table->string('name');
                $table->string('email')->unique();
                $table->string('password');
                $table->rememberToken();
                $table->timestamps();
            });
        }
### 三、执行如下命令（在数据库中生成表）
    php artisan migrate
### 四、执行如下命令（为admins表创建Model）
    php artisan make:model Admin
### 五、修改Admin Model的内容（可以完全与User model一样，复制过来就行了）
    <?php
    
    namespace App;
    
    use Illuminate\Notifications\Notifiable;
    use Illuminate\Foundation\Auth\User as Authenticatable;
    
    class Admin extends Authenticatable   //这里复制过来的时候不要忘记修改User为Admin
    {
        use Notifiable;  //这个是用来发送消息的如忘记密码，重置密码时发送email的
    
        /**
         * The attributes that are mass assignable.
         *
         * @var array
         */
        protected $fillable = [
            'name', 'email', 'password',
        ];
    
        /**
         * The attributes that should be hidden for arrays.
         *
         * @var array
         */
        protected $hidden = [
            'password', 'remember_token',
        ];
    }
### 六、理解config->auth.app里面各个配置的作用，并修改里面的内容（添加admin相关配置）
    <?php
    
    return [
    
        /*
        |--------------------------------------------------------------------------
        | 用户认证默认配置
        |--------------------------------------------------------------------------
        |
        | 这里是控制默认的'guard'和密码重置时该使用哪个的选项。基本上不用修改
        | 如果不想使用默认的guard即Auth:: 可以在任何地方使用如：Auth::guard('admin')来切换成admin
        */
    
        'defaults' => [
            'guard' => 'web',
            'passwords' => 'users',
        ],
    
        /*
        |--------------------------------------------------------------------------
        | 用户认证的 Guards 配置
        |--------------------------------------------------------------------------
        |
        | 这里的guard dirver 一般分两种，一种是直接web访问，使用的session
        | 另外一种是使用api，用的是token
        |
        */
    
        'guards' => [
            'web' => [
                'driver' => 'session',
                'provider' => 'users',
            ],
    
            'api' => [
                'driver' => 'token',
                'provider' => 'users',
            ],
            
            'admin' => [
                'driver' => 'session',
                'provider' => 'admins',
            ],
            
            'admin-api' => [
                'driver' => 'token',
                'provider' => 'admins',
            ],
        ],
    
        /*
        |--------------------------------------------------------------------------
        | 用户 Providers配置
        |--------------------------------------------------------------------------
        |
        | 每个用户都需要配置一个provider，它的作用是指定哪个provider与数据库的哪个用户表的数据项关联
        | driver 支持: "database", "eloquent" 两种模式
        |
        */
    
        'providers' => [
            'users' => [
                'driver' => 'eloquent',
                'model' => App\User::class,
            ],
            
            'admins' => [
                'driver' => 'eloquent',
                'model' => App\Admin::class,
            ],
    
            // 'users' => [
            //     'driver' => 'database',
            //     'table' => 'users',
            // ],
        ],
    
        /*
        |--------------------------------------------------------------------------
        | 重置密码配置项
        |--------------------------------------------------------------------------
        |
        | 如果有多用户时，那么在重置密码时就会用到这里了，它可以指定用户使用哪个表来重置密码
        | 
        | expire 选项，是用来设置token的有效期的，默认为1分钟，这里可以根据需要修改
        |
        */
    
        'passwords' => [
            'users' => [
                'provider' => 'users',
                'table' => 'password_resets',
                'expire' => 60,
            ],
            
            'admins' => [
                'provider' => 'admins',
                'table' => 'password_resets',//这里就和user用同一张表了重置密码就可以了
                'expire' => 30,
            ],
        ],
    
    ];
### 七、在Admin Model里面设置$guard='admin'，即在里面添加如下代码：
    protected $guard = 'admin'; //申明Admin这个Model需要使用的admin这个guard  
### 八、在web.php路由文件添加一条路由，设置admin管理员用户登录后需要进入到的主页：
    Route::prefix('admin')->group(function (){
        Route::get('/', 'AdminController@index')->name('admin.dashboard'); 
    });
### 九、创建AdminController，执行如下命令：
    php artisan make:controller AdminController
### 十、修改AdminController的内容如下(其实可以复制HomeController也行)：
    <?php
    
    namespace App\Http\Controllers;
    
    use Illuminate\Http\Request;
    
    class AdminController extends Controller
    {
        /**
         * Create a new controller instance.
         *
         * @return void
         */
        public function __construct()
        {
            $this->middleware('auth');
        }
    
        /**
         * Show the application dashboard.
         *
         * @return \Illuminate\Http\Response
         */
        public function index()
        {
            return view('admin');
        }
    }
### 十一、在views下创建admin.blade.php内容如下：(可以复制home.blade.php修改一下)
    @extends('layouts.app')
    
    @section('content')
    <div class="container">
        <div class="row">
            <div class="col-md-8 col-md-offset-2">
                <div class="panel panel-default">
                    <div class="panel-heading">Admin Dashboard</div>
    
                    <div class="panel-body">
                        You are logged in <strong>Admin</strong>
                    </div>
                </div>
            </div>
        </div>
    </div>
    @endsection
### 十二、！！这里需要注意了！！，到目前为止，用户可以注册并登录并成功访问了home了，但是admin没有登录，却也可以访问到admin页面，这是不对的，那么就需要进入AdminController进行控制（修改__construct代码）：
    public function __construct()
    {
        $this->middleware('auth:admin');将'auth'改为-->'auth:admin',即使用admin guard来控制
    }
### 十三、实现admin用户登录功能
#### 1、实现admin登录窗口
##### ①、在Controllers->Auth->Admin下创建LoginController执行如下命令：
    php artisan make:controller LoginController
##### ②、在Controllers->Auth目录下创建Admin文件夹，然后将上面新创建的LoginController移到Admin文件夹里面。
##### ③、修改新创建的LoginController,内容如下(可以复制Auth下面的LoginController，改一下内容即可)：
    <?php
    
    namespace App\Http\Controllers\Auth\Admin;  //这里的命名空间一定要改正确
    
    use App\Http\Controllers\Controller;
    use Illuminate\Foundation\Auth\AuthenticatesUsers;
    
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
        protected $redirectTo = '/admin';  //这里的跳转路径要改成admin的成功登陆后的哪个路径
    
        /**
         * Create a new controller instance.
         *
         * @return void
         */
        public function __construct()
        {
            $this->middleware('guest:admin')->except('logout'); //这里给middleware添加一个admin guard
        }
    }
##### ④、在views->auth->admin目录下创建Admin用户登陆的视图login.blade.php，内容为(可以与auth下面的login.blade.php一样，修改一下即可)：
    @extends('layouts.app')
    
    @section('content')
    <div class="container">
        <div class="row">
            <div class="col-md-8 col-md-offset-2">
                <div class="panel panel-default">
                    <div class="panel-heading">Admin Login</div> //修改第一处：添加Admin
                    <div class="panel-body">
                        <form class="form-horizontal" role="form" method="POST" action="{{ route('admin.login') }}"> //修改第二处：修改route为：'admin.login'
                            {{ csrf_field() }}
    
                            <div class="form-group{{ $errors->has('email') ? ' has-error' : '' }}">
                                <label for="email" class="col-md-4 control-label">E-Mail Address</label>
    
                                <div class="col-md-6">
                                    <input id="email" type="email" class="form-control" name="email" value="{{ old('email') }}" required autofocus>
    
                                    @if ($errors->has('email'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('email') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>
    
                            <div class="form-group{{ $errors->has('password') ? ' has-error' : '' }}">
                                <label for="password" class="col-md-4 control-label">Password</label>
    
                                <div class="col-md-6">
                                    <input id="password" type="password" class="form-control" name="password" required>
    
                                    @if ($errors->has('password'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('password') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>
    
                            <div class="form-group">
                                <div class="col-md-6 col-md-offset-4">
                                    <div class="checkbox">
                                        <label>
                                            <input type="checkbox" name="remember" {{ old('remember') ? 'checked' : '' }}> Remember Me
                                        </label>
                                    </div>
                                </div>
                            </div>
    
                            <div class="form-group">
                                <div class="col-md-8 col-md-offset-4">
                                    <button type="submit" class="btn btn-primary">
                                        Login
                                    </button>
    
                                    <a class="btn btn-link" href="{{ route('password.request') }}">
                                        Forgot Your Password?
                                    </a>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    @endsection

##### ⑤、在web.php路由文件里面创建一个新的路由用来显示Admin用户登录窗口：
    Route::prefix('admin')->group(function (){
        Route::get('/', 'AdminController@index')->name('admin.dashboard');
        Route::get('/login','Auth\Admin\LoginController@showLoginForm')->name('admin.login'); //此为新添加的
    });
##### ⑥、！！这里需要注意了！！，需要在Admin下面的LoginController里面重构showLoginForm代码，即添加如下代码：
    public function showLoginForm()  
    {
        return view('auth.admin.login'); //重构代码，此为AuthenticatesUsers里面的方法
    }
#### 2、实现admin登录功能：
##### ①、首先需要创建一个超级管理员用户信息，因为是管理员后台，不需要注册功能，直接用PHP Tinker创建一个超级管理员的信息，以后由超级管理员来添加管理员即可，分别执行如下命令：
    php artisan tinker
    $admin = new App\Admin;
    $admin->name = '余亭';
    $admin->email = 'yuting@email.com';
    $admin->password = bcrypt('123456');
    $admin->save();
##### ②、在web.php路由文件里面创建一个新的路由用来实现Admin用户登录跳转功能：
    Route::prefix('admin')->group(function (){
        Route::get('/', 'AdminController@index')->name('admin.dashboard');
        Route::get('/login','Auth\Admin\LoginController@showLoginForm')->name('admin.login');
        Route::post('/login','Auth\Admin\LoginController@login')->name('admin.login.submit');//新添加的路由
    });
##### ③、重构Admin下面的LoginController里面的login方法：
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
#### 总结2：到此为止实现了admin的登录功能，但是需要注意的地方是，各个页面的相互跳转是不正常的。下面就来修正这个问题。
#### 3、修正页面相互跳转bug：
##### ①、要想解决页面跳转bug，需要从两个方面来理解，第一：登录的页面（即login页）只有没有登录的用户才能看到，如果是登录后的用户就直接跳转到dashboard页面了，那么这个登录页面就需要一个中间件来控制，这个中间件就是guest，位于Http->kernel.php文件里面的$routeMiddleware里面；第二：如果是规定了必须登录后才能看到的页面，是用auth中间件来控制的，auth中间件也是位于Http->kernel.php里面，但是注意，这个中间件比较特殊，如果没有通过auth这个中间件的验证即unauthenticated，那么它会抛出异常即Exception，那么unauthenticated()这个方法就是处理用户认证失败的异常处理，位于Exceptions文件夹里面的Handler.php文件里面的。
##### ②、修改Exceptions->Handler.php->unauthenticated()方法：
    protected function unauthenticated($request, AuthenticationException $exception)
    {
        if ($request->expectsJson()) {
            return response()->json(['error' => 'Unauthenticated.'], 401);
        }
        $guard = array_get($exception->guards(),0);//取得没有通过验证的是哪个guard
        switch ($guard){
            case 'admin'://如果是auth中间件没通过验证的guard是admin的话
                return redirect()->guest(route('admin.login'));
            break;
            case '': //如果是auth中间件没通过验证的guard是空的话，即web（因为默认为web）
            //default://默认值，即web。因此用这代替case '':也行的。
                return redirect()->guest(route('login'));
            break;
        }
    }
##### ③、修改guest中间件里面的handel()方法，即\App\Http\Middleware\RedirectIfAuthenticated中间件里面的handel()方法。
    public function handle($request, Closure $next, $guard = null)
    {
        switch ($guard){
            case 'admin':
                if (Auth::guard($guard)->check()) {
                    return redirect()->route('admin.dashboard');
                }
            break;
            case '':
                if (Auth::guard($guard)->check()) {
                    return redirect('/home');
                }
            break;
        }
        return $next($request);
    }
#### 4、修正退出登录的时候，user和admin同时都退出的问题：
##### ①、首先解决user退出登录时，只退出user的，不影响admin用户，那么就需要到Auth->LoginController.php里面重构AuthenticatesUsers里面的logout()方法：
    public function logout()
    {  //里面需要去掉$request->session()->flush();$request->session()->regenerate();不然会影响所有的session的
        Auth::guard('web')->logout();
        return redirect('/');
    }
##### ②、然后需要到web.php路由文件为logout()方法添加一条路由：
    Route::post('/user/logout', 'Auth\LoginController@logout')->name('user.logout');
##### ③、同样需要在Auth->Admin->LoginController里面重构logout()方法：
    public function logout()
    {  //里面需要去掉$request->session()->flush();$request->session()->regenerate();不然会影响所有的session的
        Auth::guard('admin')->logout();
        return redirect('/');
    }
##### ④、如果要让admin的logout起作用，还需要在web.php路由文件里面给它配置一条路由：
    Route::post('/logout','Auth\Admin\LoginController@logout')->name('admin.logout');
##### ⑤、由于user和admin的页面都是引用了同一个layouts->app.php模板文件，那么就需要判断退出登录时该使用那条路由才能正确退出，修改app.blade退出登录的代码如下：
    @if(substr(Auth::guard()->getName(),6,3) == 'adm') //这是判断当前使用的guard对应的session名字来判断是admin还是user。
        <a href="{{ route('admin.logout') }}"
           onclick="event.preventDefault();
             document.getElementById('logout-form').submit();">
            Logout
        </a>
    
        <form id="logout-form" action="{{ route('admin.logout') }}" method="POST" style="display: none;">
            {{ csrf_field() }}
        </form>
    @else
        <a href="{{ route('user.logout') }}"
           onclick="event.preventDefault();
             document.getElementById('logout-form').submit();">
            Logout
        </a>
    
        <form id="logout-form" action="{{ route('user.logout') }}" method="POST" style="display: none;">
            {{ csrf_field() }}
        </form>
    @endif
### 十四、实现admin用户忘记密码和重置密码功能：
#### 1、要实现此功能需要先了解laravel自带的user用户忘记密码和重置密码功能的步骤：
##### 步骤①、在登录界面点击‘Forgot Your Password?’即‘忘记密码’链接进入到‘发送验证邮箱界面’；
##### 步骤②、在‘发送验证邮箱界面’里面输入注册时的邮箱，点击‘Send Password Reset Link’按钮，发送验证消息到输入的邮箱地址；
##### 步骤③、用户登录自己的邮箱，查看刚刚发送的验证信息邮件，点击里面的url链接地址，进入到‘重置密码界面’；
##### 步骤④、用户在‘重置密码界面’输入密码后，点击重置密码按钮，将重新设置的密码，和token保存到数据表中，并登录当前用户到dashboard。
#### 2、那么就来实现admin用户忘记密码重置密码功能了：
##### ①、修改views->auth->admin->login.blade.php的忘记密码链接地址：
    <a class="btn btn-link" href="{{ route('admin.password.request') }}"> //将route('password.request')改为：route('admin.password.request')
        Forgot Your Password?
    </a>
##### ②、同时在web.php路由文件添加名为：admin.password.request的路由：
    Route::prefix('admin')->group(function (){
        Route::get('/', 'AdminController@index')->name('admin.dashboard');
        Route::get('/login','Auth\Admin\LoginController@showLoginForm')->name('admin.login');
        Route::post('/login','Auth\Admin\LoginController@login')->name('admin.login.submit');
        Route::post('/logout','Auth\Admin\LoginController@logout')->name('admin.logout');
    
        Route::get('/password/reset','Auth\Admin\ForgotPasswordController@showLinkRequestForm')->name('admin.password.request');//此为新添加的路由
    });
##### ③、同时创建Auth\Admin\ForgotPasswordController controller，内容为（可以复制user的ForgotPasswordController修改一下即可）：
    <?php
    
    namespace App\Http\Controllers\Auth\Admin;
    
    use App\Http\Controllers\Controller;
    use Illuminate\Foundation\Auth\SendsPasswordResetEmails;
    
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
##### ④、auth->admin->passwords->email.blade.php文件内容为：
    @extends('layouts.app')
    
    @section('content')
    <div class="container">
        <div class="row">
            <div class="col-md-8 col-md-offset-2">
                <div class="panel panel-default">
                    <div class="panel-heading">Admin Reset Password</div>//修改为Admin的标记
                    <div class="panel-body">
                        @if (session('status'))
                            <div class="alert alert-success">
                                {{ session('status') }}
                            </div>
                        @endif
    
                        <form class="form-horizontal" role="form" method="POST" action="{{ route('admin.password.email') }}">//这里必须换成admin的提交路径
                            {{ csrf_field() }}
    
                            <div class="form-group{{ $errors->has('email') ? ' has-error' : '' }}">
                                <label for="email" class="col-md-4 control-label">E-Mail Address</label>
    
                                <div class="col-md-6">
                                    <input id="email" type="email" class="form-control" name="email" value="{{ old('email') }}" required>
    
                                    @if ($errors->has('email'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('email') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>
    
                            <div class="form-group">
                                <div class="col-md-6 col-md-offset-4">
                                    <button type="submit" class="btn btn-primary">
                                        Send Password Reset Link
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    @endsection
##### ⑤、到web.php路径文件添加一条名为：admin.password.email的路由：
    Route::prefix('admin')->group(function (){
        Route::get('/', 'AdminController@index')->name('admin.dashboard');
        Route::get('/login','Auth\Admin\LoginController@showLoginForm')->name('admin.login');
        Route::post('/login','Auth\Admin\LoginController@login')->name('admin.login.submit');
        Route::post('/logout','Auth\Admin\LoginController@logout')->name('admin.logout');
    
        Route::get('/password/reset','Auth\Admin\ForgotPasswordController@showLinkRequestForm')->name('admin.password.request');
        Route::post('/password/email','Auth\Admin\ForgotPasswordController@sendResetLinkEmail')->name('admin.password.email');//此为新增加的路由
    });
##### ⑥、！！重点，难点来了！！实现如何发送邮件，要理解，必须一步步深入进去：
    1、实现进入ForgotPasswordController，里面有use SendsPasswordResetEmails；
    2、进入Illuminate\Foundation\Auth\SendsPasswordResetEmails,里面有sendResetLinkEmail方法；
    3、sendResetLinkEmail()方法里面有sendResetLink()方法，那么这个方法是在Illuminate\Auth\Passwords\PasswordBroker里面；
    *4、sendResetLink()方法里面又有sendPasswordResetNotification()方法，
        $user->sendPasswordResetNotification(  //由此可看出该方法是依赖于Model的，所以需要在Admin Model里面重构该发送邮件的方法，这是重点，必须注意。
           $this->tokens->create($user)
        );
    5、sendPasswordResetNotification()方法位于：Illuminate\Contracts\Auth\CanResetPassword里面：
        public function sendPasswordResetNotification($token)
        {
            $this->notify(new ResetPasswordNotification($token));
        }
##### ⑦、在Admin Model里面重构sendPasswordResetNotification()方法：
    public function sendPasswordResetNotification($token)
    {
        $this->notify(new AdminResetPasswordNotification($token));//这是需要由new ResetPasswordNotification($token)改成new AdminResetPasswordNotification($token)
    }
##### ⑧、创建AdminResetPasswordNotification，执行如下命令：
    php artisan make:notification AdminResetPasswordNotification
##### ⑨、内容为：
    <?php
    
    namespace App\Notifications;
    
    use Illuminate\Bus\Queueable;
    use Illuminate\Notifications\Notification;
    use Illuminate\Contracts\Queue\ShouldQueue;
    use Illuminate\Notifications\Messages\MailMessage;
    
    class AdminResetPasswordNotification extends Notification
    {
        use Queueable;
    
        public $token;//这里需要用public 申明
        
        public function __construct($token)
        {
            $this->token =$token;
        }
         
        public function via($notifiable)
        {
            return ['mail'];
        }
         
        public function toMail($notifiable)
        {
            return (new MailMessage)
                ->line('请点击链接进入修改密码界面')
                ->action('修改密码', route('admin.password.reset',$this->token))//链接到修改密码界面,注意，token不要忘记携带了
                ->line('Thank you for using our application!');
        }
    
        /**
         * Get the array representation of the notification.
         *
         * @param  mixed  $notifiable
         * @return array
         */
        public function toArray($notifiable)
        {
            return [
                //
            ];
        }
    }

##### ⑩、再为修改密码界面添加一条名为：admin.password.reset的路由：
    Route::prefix('admin')->group(function (){
        Route::get('/', 'AdminController@index')->name('admin.dashboard');
        Route::get('/login','Auth\Admin\LoginController@showLoginForm')->name('admin.login');
        Route::post('/login','Auth\Admin\LoginController@login')->name('admin.login.submit');
        Route::post('/logout','Auth\Admin\LoginController@logout')->name('admin.logout');
    
        Route::get('/password/reset','Auth\Admin\ForgotPasswordController@showLinkRequestForm')->name('admin.password.request');
        Route::post('/password/email','Auth\Admin\ForgotPasswordController@sendResetLinkEmail')->name('admin.password.email');
        Route::get('/password/reset/{token}','Auth\Admin\ResetPasswordController@showResetForm')->name('admin.password.reset');//此为新增加的路由
    });
##### ⑪、创建Auth\Admin\ResetPasswordController，内容为：
    <?php
    
    namespace App\Http\Controllers\Auth\Admin;
    
    use App\Http\Controllers\Controller;
    use Illuminate\Foundation\Auth\ResetsPasswords;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Auth;
    use Illuminate\Support\Facades\Password;
    
    class ResetPasswordController extends Controller
    { 
        use ResetsPasswords;   
        
        protected $redirectTo = '/admin'; //修改为admin
         
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

##### ⑫、创建auth\admin\passwords\reset.blade.php视图文件，内容：
    @extends('layouts.app')
    
    @section('content')
    <div class="container">
        <div class="row">
            <div class="col-md-8 col-md-offset-2">
                <div class="panel panel-default">
                    <div class="panel-heading">Admin Reset Password</div>//改标记Admin
    
                    <div class="panel-body">
                        @if (session('status'))
                            <div class="alert alert-success">
                                {{ session('status') }}
                            </div>
                        @endif
    
                        <form class="form-horizontal" role="form" method="POST" action="{{ route('admin.password.request') }}">//admin修改密码的提交路径
                            {{ csrf_field() }}
    
                            <input type="hidden" name="token" value="{{ $token }}">
    
                            <div class="form-group{{ $errors->has('email') ? ' has-error' : '' }}">
                                <label for="email" class="col-md-4 control-label">E-Mail Address</label>
    
                                <div class="col-md-6">
                                    <input id="email" type="email" class="form-control" name="email" value="{{ $email or old('email') }}" required autofocus>
    
                                    @if ($errors->has('email'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('email') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>
    
                            <div class="form-group{{ $errors->has('password') ? ' has-error' : '' }}">
                                <label for="password" class="col-md-4 control-label">Password</label>
    
                                <div class="col-md-6">
                                    <input id="password" type="password" class="form-control" name="password" required>
    
                                    @if ($errors->has('password'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('password') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>
    
                            <div class="form-group{{ $errors->has('password_confirmation') ? ' has-error' : '' }}">
                                <label for="password-confirm" class="col-md-4 control-label">Confirm Password</label>
                                <div class="col-md-6">
                                    <input id="password-confirm" type="password" class="form-control" name="password_confirmation" required>
    
                                    @if ($errors->has('password_confirmation'))
                                        <span class="help-block">
                                            <strong>{{ $errors->first('password_confirmation') }}</strong>
                                        </span>
                                    @endif
                                </div>
                            </div>
    
                            <div class="form-group">
                                <div class="col-md-6 col-md-offset-4">
                                    <button type="submit" class="btn btn-primary">
                                        Reset Password
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    @endsection

##### ⑬、再到web.php路由文件添加一条名为：admin.password.request的Post路由：
    Route::prefix('admin')->group(function (){
        Route::get('/', 'AdminController@index')->name('admin.dashboard');
        Route::get('/login','Auth\Admin\LoginController@showLoginForm')->name('admin.login');
        Route::post('/login','Auth\Admin\LoginController@login')->name('admin.login.submit');
        Route::post('/logout','Auth\Admin\LoginController@logout')->name('admin.logout');
    
        Route::get('/password/reset','Auth\Admin\ForgotPasswordController@showLinkRequestForm')->name('admin.password.request');
        Route::post('/password/email','Auth\Admin\ForgotPasswordController@sendResetLinkEmail')->name('admin.password.email');
        Route::get('/password/reset/{token}','Auth\Admin\ResetPasswordController@showResetForm')->name('admin.password.reset');
        Route::post('/password/reset','Auth\Admin\ResetPasswordController@reset'); //此为新增加的路由。
    });