package com.ygyin.apiplatformgateway;

import com.ygyin.apiplatformcommon.model.entity.InterfaceInfo;
import com.ygyin.apiplatformcommon.model.entity.User;
import com.ygyin.apiplatformcommon.service.InterfaceInfoGatewayService;
import com.ygyin.apiplatformcommon.service.UserApiInfoGatewayService;
import com.ygyin.apiplatformcommon.service.UserGatewayService;
import com.ygyin.apiplatformsdk.utils.SignatureUtil;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 网关实现全局过滤
 */
@Slf4j
@Component
public class GatewayGlobalFilter implements GlobalFilter, Ordered {

    @DubboReference
    private UserGatewayService userGatewayService;

    @DubboReference
    private InterfaceInfoGatewayService interfaceInfoGatewayService;

    @DubboReference
    private UserApiInfoGatewayService userApiInfoGatewayService;

    private static final List<String> WHITE_LIST = Arrays.asList("127.0.0.1");

    private static final String API_HOST = "http://localhost:8234";

    /**
     * 过滤器
     *
     * @param exchange 路由交换机
     * @param chain    责任链（多个 filter 从上到下构成责任链）
     * @return
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 1. 用户发送请求到 API 网关，已通过配置获取对应 /api 前缀的请求
        // 2. 记录请求日志
        ServerHttpRequest req = exchange.getRequest();
        String path = req.getPath().value();
        String url=API_HOST+path;
        String method = req.getMethod().toString();
        log.info("========== 请求日志 ============");
        log.info("请求唯一标识: " + req.getId());
        log.info("请求路径: " + path);
        log.info("url: " + url);
        log.info("请求方法: " + method);
        log.info("请求参数: " + req.getQueryParams());
        log.info("请求来源地址: " + req.getRemoteAddress());
        log.info("请求本地地址: " + req.getLocalAddress());
        log.info("my global filter");

        ServerHttpResponse resp = exchange.getResponse();

        // 3. 黑白名单，对 ip 做访问控制
        if (!WHITE_LIST.contains(req.getRemoteAddress().getHostString())) {
            resp.setStatusCode(HttpStatus.FORBIDDEN);
            return resp.setComplete();
        }

        // 4. 对用户进行鉴权，检验 ak sk 是否合法，通过 request 获取请求头信息
        HttpHeaders headers = req.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String randomNum = headers.getFirst("randomNum");
        String timestamp = headers.getFirst("timestamp");
        String signature = headers.getFirst("signature");
        String paramBody = headers.getFirst("paramBody");

        // 对 ak，sk 做校验，正常应该从 db 中获取看是否分配对应 ak
        //  根据 ak 查到当前调用接口的用户后再校验 sk
//        if (!accessKey.equals("yygg"))
//            return noAuthResponse(resp);

        User callUser = null;
        try {
            callUser = userGatewayService.getCallUser(accessKey);
        } catch (Exception e) {
            // 数据库中不匹配或不存在对应 ak 的用户
            log.error("Called User with ak is not found", e);
        }
        // 调用接口的用户为空，
        if (callUser == null)
            return noAuthResponse(resp);

        if (Long.parseLong(randomNum) > 10000)
            return noAuthResponse(resp);

        // 签名时间和当前时间不能超过 xx min
        // if(timestamp) {...}
        long curTime = System.currentTimeMillis() / 1000;
        long timeGap = 60 * 5L;
        if ((curTime - Long.parseLong(timestamp)) >= timeGap)
            return noAuthResponse(resp);

        // todo 实际应该从 db 中查该用户 secretKey
        // 服务器中将从 db 中取出来 sk 对 body 进行加密签名，再和用户的加密签名做比对
//        String serverSignature = SignatureUtil.generateSignature(paramBody, "abcabc");
        String secretKey = callUser.getSecretKey();
        String serverSignature = SignatureUtil.generateSignature(paramBody, secretKey);
        if (signature == null || !signature.equals(serverSignature))
            return noAuthResponse(resp);

        // 5. 检查请求的接口是否存在，判断 interface_info 表中是否存在对应的接口
        // 从 db 中查询接口是否存在，请求方法是否匹配
        // 业务层面上的请求参数一般不要在全局网关上做校验，业务层面自己做校验
        InterfaceInfo callInterface = null;

        try {
            callInterface = interfaceInfoGatewayService.getCallInterfaceInfo(url, method);
        } catch (Exception e) {
            // 被调用接口不存在
            log.error("Called interface is not found", e);
        }
        if (callInterface == null)
            return noAuthResponse(resp);


        // 6. 将请求进行转发，调用接口
        // (实际上 chain.filter() 为异步操作，return filter 后才开始调用接口)
//        Mono<Void> filter = chain.filter(exchange);

        // 7. 应该等接口调用完成才记录响应日志
//        log.info("调用接口响应信息: " + resp.getStatusCode());
        // 不使用 aop 前，需要在每个接口调用接口完成后，统计次数 + 1



        // 9. 若调用失败则返回对应状态码
//        if (resp.getStatusCode() != HttpStatus.OK)
//            return callErrorResponse(resp);

        // 当前 filter 过滤结束，相当于 next 找下一个过滤器
        // return chain.filter(exchange);

        // todo 发送请求前应该校验是否还有调用次数
        // 将请求进行转发，调用接口，并记录响应日志
        return handleRespWithLog(exchange, chain, callInterface.getId(), callUser.getId());
    }

    private Mono<Void> callErrorResponse(ServerHttpResponse resp) {
        resp.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return resp.setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }

    public Mono<Void> noAuthResponse(ServerHttpResponse resp) {
        resp.setStatusCode(HttpStatus.FORBIDDEN);
        return resp.setComplete();
    }

    /**
     * 处理响应并生成日志，实现在接口调用完成才记录响应日志
     *
     * @param exchange
     * @param chain
     * @return
     */
    public Mono<Void> handleRespWithLog(ServerWebExchange exchange, GatewayFilterChain chain,
                                        long apiId, long userId) {
        try {
            ServerHttpResponse resp = exchange.getResponse();
            // 获取用于缓存 data 的工厂
            DataBufferFactory dataBufferFactory = resp.bufferFactory();
            HttpStatus statusCode = resp.getStatusCode();

            if (statusCode == HttpStatus.OK) {
                // 对原响应进行装饰，增强其能力
                ServerHttpResponseDecorator decoratedResp = new ServerHttpResponseDecorator(resp) {
                    // 只有调用完转发的对应接口后才会执行
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("Body Instanceof Flux: {}", (body instanceof Flux));
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> flux = Flux.from(body);
                            // 往返回值写数据并拼接字符串
                            return super.writeWith(
                                    flux.map(dataBuffer -> {
                                        // 8. 调用接口成功后，此处让其调用次数 + 1，调用 callNumCount
                                        try {
                                            userApiInfoGatewayService.callNumCount(apiId, userId);
                                        } catch (Exception e) {
                                            log.error("CallNumCount method error", e);
                                        }

                                        // 读取到 content 并且释放内存
                                        byte[] content = new byte[dataBuffer.readableByteCount()];
                                        dataBuffer.read(content);
                                        DataBufferUtils.release(dataBuffer);

                                        // 构建响应日志
                                        StringBuilder builder = new StringBuilder(200);
                                        List<Object> respArgs = new ArrayList<>();
                                        respArgs.add(resp.getStatusCode());
                                        // 实际的调用结果 data
                                        String data = new String(content, StandardCharsets.UTF_8);
                                        builder.append(data);
                                        // 打印日志
                                        log.info("响应结果日志: " + data);
                                        return dataBufferFactory.wrap(content);

                                    })
                            );
                        } else {
                            // 9. 若调用失败则返回对应状态码
                            log.error("转发接口调用失败, 响应异常状态码: {}", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };
                // 应用装饰起模式后，将原来的 response 对象设置为装饰过的 response 对象
                return chain.filter(exchange.mutate().response(decoratedResp).build());
            }
            // 如果原来 response 的状态码出现异常，降级返回原来的数据
            return chain.filter(exchange);
        } catch (Exception e) {
            log.error("网关处理响应日志生成出现异常: " + e);
            return chain.filter(exchange);
        }
    }
}
