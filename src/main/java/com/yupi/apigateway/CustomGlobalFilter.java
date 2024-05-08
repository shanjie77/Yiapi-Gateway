package com.yupi.apigateway;

import com.api.apiclientsdk.Utils.SignUtils;
import com.api.apicommon.model.entity.InterfaceInfo;
import com.api.apicommon.model.entity.User;
import com.api.apicommon.service.InnerInterfaceInfoService;
import com.api.apicommon.service.InnerUserInterfaceInfoService;
import com.api.apicommon.service.InnerUserService;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 全局拦截
 */
@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {
    @DubboReference
    private InnerUserInterfaceInfoService innerUserInterfaceInfoService;
    @DubboReference
    private InnerUserService innerUserService;
    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;


        public static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");
        public static final String INTERFACE_HOST = "http://localhost:8123";
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //1 请求日志
        ServerHttpRequest request = exchange.getRequest();
        String path = INTERFACE_HOST+ request.getPath().value();
        String method = request.getMethod().toString();
        log.info("请求唯一标识" + request.getId());
        log.info("请求路径" + path);
        log.info("请求方法" + method);
        log.info("请求参数" + request.getQueryParams());
        String sourceAddress = request.getLocalAddress().getHostString();
        log.info("请求来源地址" + sourceAddress);
        log.info("请求来源地址" + request.getRemoteAddress());
        //拿到相应对象
        ServerHttpResponse response = exchange.getResponse();
        //2 （黑白名单）
        if(!IP_WHITE_LIST.contains(sourceAddress))
        {
            response.setStatusCode(HttpStatus.FORBIDDEN);
            return response.setComplete();
        }
        //3 用户鉴权（判断 ak、sk 是否合法）
        // 从请求头中获取参数
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String nonce = headers.getFirst("nonce");
        String timestamp = headers.getFirst("timestamp");
        String sign = headers.getFirst("sign");
        String body = headers.getFirst("body");

    // 实际情况应该是去数据库中查是否已分配给用户
        User invokeUser = null;
            try {
                //调用内部服务，根据密钥获取用户信息
                invokeUser=innerUserService.getInvokeUser(accessKey);
            }catch (Exception e)
            {
                log.error("getInvokeUser error",e);
            }
            if(invokeUser == null)
            {
                return handleNoAuth(response);
            }
//        if (!accessKey.equals("shanyi")){
//            return handleNoAuth(response);
//        }
    // 直接校验如果随机数大于1万，则抛出异常，并提示"无权限"
        if (Long.parseLong(nonce) > 10000L) {
            return handleNoAuth(response);
        }

    // 时间和当前时间不能超过5分钟
        Long currentTime =  System.currentTimeMillis()/1000;
        final Long FIVE_MINUTES = 60*5L;
        if ((currentTime - Long.parseLong(timestamp))>=FIVE_MINUTES) {
            return handleNoAuth(response);
        }

    //  实际情况中是从数据库中查出 secretKey
        //从获取到的用户信息中获取用户的密钥
        String secretKey = invokeUser.getSecretKey();
        //使用获取的密钥进行签名
        String serverSign = SignUtils.genSign(body, secretKey);
        //检查请求中的签名是否为空，或者是否与服务器生成签名不一样
        if(sign==null||!sign.equals(serverSign))
        {
            return handleNoAuth(response);
        }
        //     String serverSign = SignUtils.genSign(body, "qweasd");
    // 如果生成的签名不一致，则抛出异常，并提示"无权限"
        if (!sign.equals(serverSign)) {
            return handleNoAuth(response);
        }
        //4 请求的模拟接口是否存在？
        //从数据库中查询模拟接口是否存在，以及请求方法是否相匹配
        //初始化一个InterfaceInfo对象，用于存储查询结果
        InterfaceInfo interfaceInfo=null;
        try {
            //调用内部服务，获取指定路径和方法的接口信息
            interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(path, method);
        }catch (Exception e)
        {
            log.error("getInvokeUser error",e);
        }
        //判断是否成功获取接口信息
        if(interfaceInfo == null)
        {
            return handleNoAuth(response);
        }
        //5 请求转发，调用模拟接口
       //Mono<Void> filter= chain.filter(exchange);
        //6 响应日志
        return handleResponse(exchange,chain,interfaceInfo.getId(),invokeUser.getId());
        //8 调用失败，返回一个规范的错误码
      //   log.info("custom global filter");
      //  return filter;
    }

    @Override
    public int getOrder() {
        return -1;
    }
    /**
     * 处理响应
     *
     * @param exchange
     * @param chain
     * @return
     */
    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain,long interfaceInfoId,long userId) {
        try {
            // 获取原始的响应对象
            ServerHttpResponse originalResponse = exchange.getResponse();
            // 获取数据缓冲工厂
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            // 获取响应的状态码
            HttpStatus statusCode = originalResponse.getStatusCode();

            // 判断状态码是否为200 OK(按道理来说,现在没有调用,是拿不到响应码的,对这个保持怀疑 沉思.jpg)
            if(statusCode == HttpStatus.OK) {
                // 创建一个装饰后的响应对象(开始穿装备，增强能力)
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {

                    // 重写writeWith方法，用于处理响应体的数据
                    // 这段方法就是只要当我们的模拟接口调用完成之后,等它返回结果，
                    // 就会调用writeWith方法,我们就能根据响应结果做一些自己的处理
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("body instanceof Flux: {}", (body instanceof Flux));
                        // 判断响应体是否是Flux类型
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            // 返回一个处理后的响应体
                            // (这里就理解为它在拼接字符串,它把缓冲区的数据取出来，一点一点拼接好)
                            return super.writeWith(fluxBody.map(dataBuffer -> {
                                // 调用成功，接口调用次数 + 1
                                try {
                                //调用内部用户接口信息服务，记录接口调用次数
                                    innerUserInterfaceInfoService.invokeCount(interfaceInfoId,userId);
                                }catch (Exception e)
                                {
                                    log.error("invokeCount error",e);
                                }
                                // 读取响应体的内容并转换为字节数组
                                byte[] content = new byte[dataBuffer.readableByteCount()];
                                dataBuffer.read(content);
                                DataBufferUtils.release(dataBuffer);//释放掉内存
                                // 构建日志
                                StringBuilder sb2 = new StringBuilder(200);
                                sb2.append("<--- {} {} \n");
                                List<Object> rspArgs = new ArrayList<>();
                                rspArgs.add(originalResponse.getStatusCode());
                                //rspArgs.add(requestUrl);
                                String data = new String(content, StandardCharsets.UTF_8);//data

                                sb2.append(data);
                                log.info("响应结果"+data);
                                // 将处理后的内容重新包装成DataBuffer并返回
                                return bufferFactory.wrap(content);
                            }));
                        } else {
                            log.error("<--- {} 响应code异常", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };
                // 对于200 OK的请求,将装饰后的响应对象传递给下一个过滤器链,并继续处理(设置repsonse对象为装饰过的)
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            // 对于非200 OK的请求，直接返回，进行降级处理
            return chain.filter(exchange);
        }catch (Exception e){
            // 处理异常情况，记录错误日志
            log.error("网关处理响应异常" + e);
            return chain.filter(exchange);
        }
    }
    public Mono<Void> handleNoAuth(ServerHttpResponse response)
    {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }
    public Mono<Void> handleInvokeError(ServerHttpResponse response)
    {
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }
}