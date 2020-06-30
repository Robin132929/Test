OkHttp三部曲

一、 使用

同步请求

    OkHttpClient okHttpClient=new OkHttpClient();
    Request request=new Request.Builder()
        .get()
        .url("www.baidu.com")
        .build();
    Call call =okHttpClient.newCall(request).execute();
异步请求

  OkHttpClient okHttpClient=new OkHttpClient();
    Request request=new Request.Builder()
        .get()
        .url("www.baidu.com")
        .build();
    Call call=okHttpClient.newCall(request).enqueue(new Callback() {
      @Override public void onFailure(Call call, IOException e) {
        Log.i(TAG, "onFailure: ");
      }

      @Override public void onResponse(Call call, Response response) throws IOException {
        Log.i(TAG, "onResponse: ");
      }
    });
可以看出不管是同步还是异步请求，使用okhttp大致分为3个步骤：

创建okhttpclient
创建请求的request
通过client拿到call并发送请求
注：okhttpclient和request的创建均可采用构造者模式，在构造过程中可根据自己的实际也无需求设置相应的参数，如可在okhttpclient构造时添加自定义拦截器，在request构造过程中设置连接超时时间等。

二、 源码分析

首先看下OkhttpClient这个类，使用步骤的第一步就是构造OkhttpClient对象。

先贴下官方对OkhttpClient的定义

 *Factory for {@linkplain Call calls}, which can be used to send HTTP requests and read their
 * responses.
 * OkHttpClients should be shared
 
 * OkHttp performs best when you create a single {@code OkHttpClient} instance and reuse it for
 * all of your HTTP calls. This is because each client holds its own connection pool and thread
 * pools. Reusing connections and threads reduces latency and saves memory. Conversely, creating a
 * client for each request wastes resources on idle pools.
可以看出client是用于发送请求和读取响应的，每个client都有自己的connection pool and thread pools，所以不应该为每个request都构造client，这样会造成资源的浪费。

接下来看下OkHttpClient无参构造函数，由代码可知它是调用OkHttpClient的有参构造函数 ，在有参构造函数里对OkHttpClient主要属性做了初始化赋值。

  public OkHttpClient() {
    this(new Builder());
  }
  
  OkHttpClient(Builder builder) {
    this.dispatcher = builder.dispatcher;
    this.proxy = builder.proxy;
    this.protocols = builder.protocols;
    this.connectionSpecs = builder.connectionSpecs;
    this.interceptors = Util.immutableList(builder.interceptors);
    this.networkInterceptors = Util.immutableList(builder.networkInterceptors);
    this.eventListenerFactory = builder.eventListenerFactory;
    this.proxySelector = builder.proxySelector;
    this.cookieJar = builder.cookieJar;
    this.cache = builder.cache;
    this.internalCache = builder.internalCache;
    this.socketFactory = builder.socketFactory;
    ...//省略N行
  }
下面贴下OkHttpClient主要的属性

public class OkHttpClient{
    final Dispatcher dispatcher;//分发器
    final @Nullable
    Proxy proxy;//代理
    final List<Protocol> protocols;//协议
    final List<ConnectionSpec> connectionSpecs;//传输层版本和连接协议
    final List<Interceptor> interceptors;//拦截器 （okhttp核心机制）
    final List<Interceptor> networkInterceptors;//网络拦截器
    final EventListener.Factory eventListenerFactory;
    final ProxySelector proxySelector;//代理选择器
    final CookieJar cookieJar;//cookie
    final @Nullable
    Cache cache;//cache 缓存
    final @Nullable
    InternalCache internalCache;//内部缓存
    final SocketFactory socketFactory;//socket 工厂
    final @Nullable
    SSLSocketFactory sslSocketFactory;//安全套层socket工厂 用于https
    final @Nullable
    CertificateChainCleaner certificateChainCleaner;//验证确认响应书，适用HTTPS 请求连接的主机名
    final HostnameVerifier hostnameVerifier;//主机名字确认
    final CertificatePinner certificatePinner;//证书链
    final Authenticator proxyAuthenticator;//代理身份验证
    final Authenticator authenticator;//本地省份验证
    final ConnectionPool connectionPool;//链接池 复用连接
    final Dns dns; //域名
    final boolean followSslRedirects;//安全套接层重定向
    final boolean followRedirects;//本地重定向
    final boolean retryOnConnectionFailure;//重试连接失败
    final int connectTimeout;//连接超时
    final int readTimeout;//读取超时
    final int writeTimeout;//写入超时
}
OkHttpClient类还有一个需要了解的函数就是newCall，因为OkHttpClient实现Call.Factory接口所以覆写了newCall方法。

/**
   * Prepares the {@code request} to be executed at some point in the future.
   */
  @Override public Call newCall(Request request) {
    return RealCall.newRealCall(this, request, false /* for web socket */);
  }

至此OkHttpClient类我们大概了解的差不多了

然后我们看下request类，该类实例就是我们要发送的请求。它也是通过builder模式构造的。下面贴下Request的主要属性以及其构造函数。

public final class Request {
  final HttpUrl url;//请求url地址
  final String method;//请求方式
  final Headers headers;//请求头
  final @Nullable RequestBody body;//请求body
  final Map<Class<?>, Object> tags;//请求tags用来标记一类请求如 设置之后可以通过tags取消拥有该tag的请求

  Request(Builder builder) {
    this.url = builder.url;
    this.method = builder.method;
    this.headers = builder.headers.build();
    this.body = builder.body;
    this.tags = Util.immutableMap(builder.tags);
  }
  ...
}
通过Request我们可以得到我们想要的请求，然后下一步就是通过call去发送请求。 在介绍OkHttpClient类的时候我们已经说过call对象是通过OkHttpClient的newCall方法获得的。看下newCall方法 我们可知实际是通过Realcall的newBuilder来获得一个RealCall对象，也就是说真正发送请求的是RealCall，那么我们来看下RealCall这个类

final class RealCall implements Call {
  final OkHttpClient client; //realcall持有client
  private Transmitter transmitter;//暂时不知道其作用

  /** The application's original request unadulterated by redirects or auth headers. */
  final Request originalRequest;//原始请求
  final boolean forWebSocket;//

  // Guarded by this.
  private boolean executed;//请求是否执行标志位
  
  private RealCall(OkHttpClient client, Request originalRequest, boolean forWebSocket) { //构造函数
    this.client = client;
    this.originalRequest = originalRequest;
    this.forWebSocket = forWebSocket;
  }

  static RealCall newRealCall(OkHttpClient client, Request originalRequest, boolean forWebSocket) {//okhttpclient即通过该函数返回call
    // Safely publish the Call instance to the EventListener.
    RealCall call = new RealCall(client, originalRequest, forWebSocket);
    call.transmitter = new Transmitter(client, call);
    return call;
  }
RealCall实现的Call接口，其newCall函数内部通过RealCall的构造函数实例化一个call然后返回该call。也就是说实际发送请求的call就是这个。发送请求有两种方式同步和异步。我们先看下同步请求的方式，同步请求是通过 execute发送的

 @Override public Response execute() throws IOException {
    synchronized (this) {//1
      if (executed) throw new IllegalStateException("Already Executed");
      executed = true;
    }
    transmitter.timeoutEnter();
    transmitter.callStart();
    try {
      client.dispatcher().executed(this);//2
      return getResponseWithInterceptorChain();//3
    } finally {
      client.dispatcher().finished(this);//4
    }
  }

execute首先（注释1处）会synchronized来检查executed值从而确保每个请求只能执行一次。随后调用dispatcher的executed（注释2处）。

我们先大致了解下dispatcher类再看其executed。因为dispatcher分发器也算是okhttp的核心机制之一。

贴下dispatcher的主要属性

public final class Dispatcher {
  private int maxRequests = 64;//最大请求数
  private int maxRequestsPerHost = 5;//每个host的最大请求数
  private @Nullable Runnable idleCallback;//请求队列空闲回调

  /** Executes calls. Created lazily. */
  private @Nullable ExecutorService executorService; //执行请求的线程池

  /** Ready async calls in the order they'll be run. */
  private final Deque<AsyncCall> readyAsyncCalls = new ArrayDeque<>();//异步准备就绪请求队列

  /** Running asynchronous(异步） calls. Includes canceled calls that haven't finished yet. */
  private final Deque<AsyncCall> runningAsyncCalls = new ArrayDeque<>();//异步执行请求队列

  /** Running synchronous calls. Includes canceled calls that haven't finished yet. */
  private final Deque<RealCall> runningSyncCalls = new ArrayDeque<>();//同步请求队列
可以看出okhttp虽然支持并发请求但是有最大并发请求数的限制。而且okhttp根据不同的请求方式分为不同的请求队列。dispatcher这个类主要的作用就是根据request的请求方式以及根据当前client的执行情况把新创建的call请求分发至不同的队列中去执行。

了解了dispatcher类作用我们看下它的exectued函数

 synchronized void executed(RealCall call) {
    runningSyncCalls.add(call);
  }
很简单它只是把传入的call对象添加到同步请求队列中（runningSyncCalls）。

现在回到RealCall的exectued函数注释3处，调用了getResponseWithInterceptorChain()获取respone并返回该respone。

 Response getResponseWithInterceptorChain() throws IOException {
    // Build a full stack of interceptors.
    List<Interceptor> interceptors = new ArrayList<>();
    interceptors.addAll(client.interceptors());//如果在client中设置了自定义interceptor那么会放到interceptors中
    interceptors.add(new RetryAndFollowUpInterceptor(client));//添加重试与重定向拦截器
    interceptors.add(new BridgeInterceptor(client.cookieJar()));//添加桥接拦截器
    interceptors.add(new CacheInterceptor(client.internalCache()));//添加缓存拦截器
    interceptors.add(new ConnectInterceptor(client));
    if (!forWebSocket) {
      interceptors.addAll(client.networkInterceptors());
    }
    interceptors.add(new CallServerInterceptor(forWebSocket));//添加CallServer拦截器
//TODO
    Interceptor.Chain chain = new RealInterceptorChain(interceptors, transmitter, null, 0,
        originalRequest, this, client.connectTimeoutMillis(),
        client.readTimeoutMillis(), client.writeTimeoutMillis());//
        创建RealInterceptorChain实例，把interceptors传入

    boolean calledNoMoreExchanges = false;
    try {
      Response response = chain.proceed(originalRequest);//通过proceed链式获取respone
      if (transmitter.isCanceled()) {
        closeQuietly(response);
        throw new IOException("Canceled");
      }
      return response;//返回respone
    } catch (IOException e) {
      calledNoMoreExchanges = true;
      throw transmitter.noMoreExchanges(e);
    } finally {
      if (!calledNoMoreExchanges) {
        transmitter.noMoreExchanges(null);
      }
    }
  }
getResponseWithInterceptorChain首先会把自定义以及okhttp定义的拦截器加到interceptors的list中，然后创建RealInterceptorChain拦截器链，调用chain.proceed链式调用各个拦截器并最终获得respone。

Interceptor也是okhttp的核心机制，我们一起来看下

public interface Interceptor {
  Response intercept(Chain chain) throws IOException;

  interface Chain {
    Request request();

    Response proceed(Request request) throws IOException;

    /**
     * Returns the connection the request will be executed on. This is only available in the chains
     * of network interceptors; for application interceptors this is always null.
     */
    @Nullable Connection connection();

    Call call();

    int connectTimeoutMillis();

    Chain withConnectTimeout(int timeout, TimeUnit unit);

    int readTimeoutMillis();

    Chain withReadTimeout(int timeout, TimeUnit unit);

    int writeTimeoutMillis();

    Chain withWriteTimeout(int timeout, TimeUnit unit);
  }
}
它是okhttp定义的一个接口类，并且okhttp提供了5个实现类，他们分别是

a a
他们的作用看这里

除此之外我们还可以自定义自己的拦截器。

了解了拦截器的概念之后我们看下RealInterceptorChain及其proceed函数

public final class RealInterceptorChain implements Interceptor.Chain {
  private final List<Interceptor> interceptors;//拦截器list
  private final Transmitter transmitter;
  private final @Nullable Exchange exchange;
  private final int index;
  private final Request request;//请求
  private final Call call;
  private final int connectTimeout;
  private final int readTimeout;
  private final int writeTimeout;
  private int calls;

  public RealInterceptorChain(List<Interceptor> interceptors, Transmitter transmitter,
      @Nullable Exchange exchange, int index, Request request, Call call,
      int connectTimeout, int readTimeout, int writeTimeout) {//构造函数
    this.interceptors = interceptors;
    this.transmitter = transmitter;
    this.exchange = exchange;
    this.index = index;
    this.request = request;
    this.call = call;
    this.connectTimeout = connectTimeout;
    this.readTimeout = readTimeout;
    this.writeTimeout = writeTimeout;
  }
@Override public Response proceed(Request request) throws IOException {//proceed方法实际调用同名的proceed方法
    return proceed(request, transmitter, exchange);
  }

  public Response proceed(Request request, Transmitter transmitter, @Nullable Exchange exchange)
      throws IOException {//1
    if (index >= interceptors.size()) throw new AssertionError();

    calls++;

    // If we already have a stream, confirm that the incoming request will use it.
    if (this.exchange != null && !this.exchange.connection().supportsUrl(request.url())) {
      throw new IllegalStateException("network interceptor " + interceptors.get(index - 1)
          + " must retain the same host and port");
    }

    // If we already have a stream, confirm that this is the only call to chain.proceed().
    if (this.exchange != null && calls > 1) {
      throw new IllegalStateException("network interceptor " + interceptors.get(index - 1)
          + " must call proceed() exactly once");
    }

    // 2
    //Call the next interceptor in the chain.
    RealInterceptorChain next = new RealInterceptorChain(interceptors, transmitter, exchange,
        index + 1, request, call, connectTimeout, readTimeout, writeTimeout);
    Interceptor interceptor = interceptors.get(index);
    Response response = interceptor.intercept(next);

    // Confirm that the next interceptor made its required call to chain.proceed().
    if (exchange != null && index + 1 < interceptors.size() && next.calls != 1) {
      throw new IllegalStateException("network interceptor " + interceptor
          + " must call proceed() exactly once");
    }

    // Confirm that the intercepted response isn't null.
    if (response == null) {
      throw new NullPointerException("interceptor " + interceptor + " returned null");
    }

    if (response.body() == null) {
      throw new IllegalStateException(
          "interceptor " + interceptor + " returned a response with no body");
    }

    return response;
  }
该类的proceed方法实际是调用了该类的另一个同名的proceed方法（注释1处）。同名proceed内部首先会做一些条件判断，我们暂时可以不用关心。主要看下注释2处，调用拦截器链中的下一个拦截器。在这里new了一个RealInterceptorChain，注意这里传入的index加了1，这代表拦截器链中的下一个拦截器的index，之后根据index获取当前的拦截器并调用其intercept方法。intercept是接口Interceptor的一个方法，由具体的实现类实现，此处我们以RetryAndFollowUpInterceptor为例看下intercept方法中做了什么事情。

public final class RetryAndFollowUpInterceptor implements Interceptor {
  private final OkHttpClient client;//持有的client
@Override public Response intercept(Chain chain) throws IOException {
    Request request = chain.request();//获取传入的chain的request 此处的request是next的request
    RealInterceptorChain realChain = (RealInterceptorChain) chain;
    Transmitter transmitter = realChain.transmitter();

    int followUpCount = 0;
    Response priorResponse = null;
    while (true) {
      transmitter.prepareToConnect(request);

      if (transmitter.isCanceled()) {
        throw new IOException("Canceled");
      }

      Response response;
      boolean success = false;
      try {
        response = realChain.proceed(request, transmitter, null);//调用next的proceed方法
        success = true;
      } catch (RouteException e) {
        // The attempt to connect via a route failed. The request will not have been sent.
        if (!recover(e.getLastConnectException(), transmitter, false, request)) {
          throw e.getFirstConnectException();
        }
        continue;
      } catch (IOException e) {
        // An attempt to communicate with a server failed. The request may have been sent.
        boolean requestSendStarted = !(e instanceof ConnectionShutdownException);
        if (!recover(e, transmitter, requestSendStarted, request)) throw e;
        continue;
      } finally {
        // The network call threw an exception. Release any resources.
        if (!success) {
          transmitter.exchangeDoneDueToException();
        }
      }

      // Attach the prior response if it exists. Such responses never have a body.
      if (priorResponse != null) {
        response = response.newBuilder()
            .priorResponse(priorResponse.newBuilder()
                    .body(null)
                    .build())
            .build();
      }

      Exchange exchange = Internal.instance.exchange(response);
      Route route = exchange != null ? exchange.connection().route() : null;
      Request followUp = followUpRequest(response, route);//请求重定向

      if (followUp == null) {
        if (exchange != null && exchange.isDuplex()) {
          transmitter.timeoutEarlyExit();
        }
        return response;//直到没有重定向之后返回respone
      }

      RequestBody followUpBody = followUp.body();
      if (followUpBody != null && followUpBody.isOneShot()) {
        return response;
      }

      closeQuietly(response.body());
      if (transmitter.hasExchange()) {
        exchange.detachWithViolence();
      }

      if (++followUpCount > MAX_FOLLOW_UPS) {
        throw new ProtocolException("Too many follow-up requests: " + followUpCount);
      }

      request = followUp;
      priorResponse = response;
    }
  }
}
我们看到在RetryAndFollowUpInterceptor的intercept方法中会调用传入的next（即拦截器链中当前拦截器的下一个拦截器）的proceed方法，这样就可以链式的依次调用chain中所有拦截器，每个拦截器都执行自己的任务最终返回respone。该respone通过RealCall的getResponseWithInterceptorChain返回到execute方法并最终变成我们获得的respone。至此同步请求获的了respone，最后的操作就是在RealCall的execute方法中调用finished方法

 @Override public Response execute() throws IOException {
    synchronized (this) {
      if (executed) throw new IllegalStateException("Already Executed");
      executed = true;
    }
    transmitter.timeoutEnter();
    transmitter.callStart();
    try {
      client.dispatcher().executed(this);
      return getResponseWithInterceptorChain();
    } finally {
      client.dispatcher().finished(this);//拿到respone后调用finish方法
    }
  }
该方法是dispatcher提供的

 void finished(RealCall call) {
    finished(runningSyncCalls, call);
  }

  private <T> void finished(Deque<T> calls, T call) {
    Runnable idleCallback;
    synchronized (this) {
      if (!calls.remove(call)) throw new AssertionError("Call wasn't in-flight!");//从同步执行队列移除该call 移除失败会抛出异常
      idleCallback = this.idleCallback;
    }

    boolean isRunning = promoteAndExecute();//判断是否还有可执行的call

    if (!isRunning && idleCallback != null) {
      idleCallback.run();//如果没有可执行的call并且idleCallback不为空就执行idleCallback。
    }
  }
异步请求

异步请求是调用RealCall的enqueue方法

@Override public void enqueue(Callback responseCallback) {
    synchronized (this) {
      if (executed) throw new IllegalStateException("Already Executed");
      executed = true;
    }
    transmitter.callStart();
    client.dispatcher().enqueue(new AsyncCall(responseCallback));//执行dispatcher的enqueue
  }
在方法内部调用dispatcher的enqueue并传入AsyncCall参数

 void enqueue(AsyncCall call) {
    synchronized (this) {
      readyAsyncCalls.add(call);//添加到异步准备就绪队列

      // Mutate the AsyncCall so that it shares the AtomicInteger of an existing running call to
      // the same host.
      if (!call.get().forWebSocket) {
        AsyncCall existingCall = findExistingCallWithHost(call.host());
        if (existingCall != null) call.reuseCallsPerHostFrom(existingCall);
      }
    }
    promoteAndExecute();//执行请求
  }
在方法内部先是把call添加到异步准备就绪队列然后调用了 promoteAndExecute，这个方法区实际的执行request请求

private boolean promoteAndExecute() {
    assert (!Thread.holdsLock(this));

    List<AsyncCall> executableCalls = new ArrayList<>();
    boolean isRunning;
    synchronized (this) {
      for (Iterator<AsyncCall> i = readyAsyncCalls.iterator(); i.hasNext(); ) {//把异步准备就绪对列中的call取出
        AsyncCall asyncCall = i.next();
        //判断最大请求数以及每个host请求数是否符合要求
        if (runningAsyncCalls.size() >= maxRequests) break; // Max capacity.
        if (asyncCall.callsPerHost().get() >= maxRequestsPerHost) continue; // Host max capacity.
        //移除准备就绪队列中的call
        i.remove();
        asyncCall.callsPerHost().incrementAndGet();//记录该call的host的请求数
        executableCalls.add(asyncCall);//添加到executableCalls
        runningAsyncCalls.add(asyncCall);//添加到异步执行队列
      }
      isRunning = runningCallsCount() > 0;
    }

    for (int i = 0, size = executableCalls.size(); i < size; i++) {//executableCalls不为空，取出执行
      AsyncCall asyncCall = executableCalls.get(i);
      asyncCall.executeOn(executorService());//call实际执行
    }

    return isRunning;
  }
在方法内部首先是取出异步准备就绪队列中的call并放到执行队列中，然后通过executeOn执行call请求。

  void executeOn(ExecutorService executorService) {
      assert (!Thread.holdsLock(client.dispatcher()));
      boolean success = false;
      try {
        executorService.execute(this);//实际执行call
        success = true;
      } catch (RejectedExecutionException e) {
        InterruptedIOException ioException = new InterruptedIOException("executor rejected");
        ioException.initCause(e);
        transmitter.noMoreExchanges(ioException);
        responseCallback.onFailure(RealCall.this, ioException);
      } finally {
        if (!success) {
          client.dispatcher().finished(this); // This call is no longer running!
        }
      }
    }
在executeOn内部调用executorService.execute执行call，此处的call实际是AsyncCall

final class AsyncCall extends NamedRunnable {
 void executeOn(ExecutorService executorService) {
 //...
   }
 }
 
AsyncCall继承自NamedRunnable

public abstract class NamedRunnable implements Runnable {
  protected final String name;

  public NamedRunnable(String format, Object... args) {
    this.name = Util.format(format, args);
  }

  @Override public final void run() {
    String oldName = Thread.currentThread().getName();
    Thread.currentThread().setName(name);
    try {
      execute();
    } finally {
      Thread.currentThread().setName(oldName);
    }
  }

  protected abstract void execute();
}

初始化client ---》初始化request ———》初始化call ——-》call.execute

实际是执行realcall的execute方法 该方法1、首先判断传入的call是否执行过 (规定每个call只能执行一次) 2、然后将call添加到同步执行队列 3、调用拦截器链得到服务端响应 4、从同步请求队列移除该call
