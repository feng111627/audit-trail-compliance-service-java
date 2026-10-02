package com.github.feng111627.audittrailcomplianceservicejava.audit.aspect;

import com.github.feng111627.audittrailcomplianceservicejava.audit.annotation.Audited;
import com.github.feng111627.audittrailcomplianceservicejava.audit.masking.MaskingService;
import com.github.feng111627.audittrailcomplianceservicejava.audit.model.OperationResult;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditSecurityContext;
import com.github.feng111627.audittrailcomplianceservicejava.audit.security.AuditUser;
import com.github.feng111627.audittrailcomplianceservicejava.audit.service.AuditService;
import com.github.feng111627.audittrailcomplianceservicejava.demo.BusinessException;
import jakarta.validation.ConstraintViolationException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.LinkedHashMap;
import java.util.Map;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * 拦截 {@link Audited} 方法自动留痕。
 *
 * <p>结果归类：
 * <ul>
 *   <li>正常返回：SUCCESS；</li>
 *   <li>抛 {@link BusinessException}：FAILED（业务规则拒绝）；</li>
 *   <li>抛校验异常：VALIDATION_REJECTED（参数校验未通过）；</li>
 *   <li>其它异常：ERROR（被中断）。</li>
 * </ul>
 * 无论成功失败都会留痕，异常在留痕后照常抛出。
 */
@Aspect
@Component
public class AuditAspect {

    private final AuditService auditService;
    private final MaskingService maskingService;
    private final ExpressionParser parser = new SpelExpressionParser();
    private final ParameterNameDiscoverer nameDiscoverer = new DefaultParameterNameDiscoverer();

    public AuditAspect(AuditService auditService, MaskingService maskingService) {
        this.auditService = auditService;
        this.maskingService = maskingService;
    }

    @Around("@annotation(audited)")
    public Object around(ProceedingJoinPoint pjp, Audited audited) throws Throwable {
        MethodSignature signature = (MethodSignature) pjp.getSignature();
        Method method = signature.getMethod();
        long start = System.nanoTime();

        Map<String, Object> parameters = audited.recordParameters()
                ? collectParameters(method, pjp.getArgs())
                : Map.of();

        OperationResult result = OperationResult.SUCCESS;
        String reason = null;
        Object value = null;
        Throwable thrown = null;
        try {
            value = pjp.proceed();
            return value;
        } catch (Throwable t) {
            thrown = t;
            result = classify(t);
            reason = reasonOf(t);
            throw t;
        } finally {
            long duration = (System.nanoTime() - start) / 1_000_000;
            String resourceId = resolveResourceId(audited, method, pjp.getArgs(), value, thrown);
            String action = resolveAction(audited, method);
            AuditUser user = AuditSecurityContext.get();
            String actor = user == null ? "anonymous" : user.username();
            try {
                auditService.record(actor, action, audited.resourceType(), resourceId,
                        parameters, result, reason, duration);
            } catch (Exception recordFailure) {
                // 留痕失败不应吞掉业务结果；此处只做兜底，避免影响主流程。
                recordFailure.printStackTrace();
            }
        }
    }

    private OperationResult classify(Throwable t) {
        if (t instanceof BusinessException) {
            return OperationResult.FAILED;
        }
        if (t instanceof ConstraintViolationException
                || isValidationException(t)) {
            return OperationResult.VALIDATION_REJECTED;
        }
        return OperationResult.ERROR;
    }

    private boolean isValidationException(Throwable t) {
        String className = t.getClass().getName();
        return className.equals("org.springframework.web.bind.MethodArgumentNotValidException")
                || className.equals("org.springframework.validation.BindException");
    }

    private String reasonOf(Throwable t) {
        String suffix = OperationResult.VALIDATION_REJECTED.equals(classify(t))
                ? "[校验拒绝] " : OperationResult.FAILED.equals(classify(t))
                ? "[业务拒绝] " : "[异常中断] ";
        String message = t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage();
        return suffix + message;
    }

    private String resolveAction(Audited audited, Method method) {
        if (!audited.action().isBlank()) {
            return audited.action();
        }
        return method.getDeclaringClass().getSimpleName() + "." + method.getName();
    }

    private Map<String, Object> collectParameters(Method method, Object[] args) {
        Map<String, Object> raw = new LinkedHashMap<>();
        String[] names = nameDiscoverer.getParameterNames(method);
        Parameter[] parameters = method.getParameters();
        for (int i = 0; i < args.length; i++) {
            if (isIgnored(args[i])) {
                continue;
            }
            String name = names != null && i < names.length ? names[i]
                    : parameters[i].getName();
            raw.put(name, maskingService.maskObject(args[i]));
        }
        return raw;
    }

    private boolean isIgnored(Object arg) {
        return arg instanceof ServletRequest || arg instanceof ServletResponse
                || arg instanceof BindingResult || arg instanceof RequestAttributes
                || arg instanceof InputStream || arg instanceof OutputStream;
    }

    private String resolveResourceId(Audited audited, Method method, Object[] args,
                                     Object result, Throwable thrown) {
        String expressionText = audited.resourceId();
        if (expressionText == null || expressionText.isBlank()) {
            return null;
        }
        try {
            EvaluationContext context = new StandardEvaluationContext();
            String[] names = nameDiscoverer.getParameterNames(method);
            for (int i = 0; i < args.length; i++) {
                String name = names != null && i < names.length ? names[i]
                        : method.getParameters()[i].getName();
                context.setVariable(name, args[i]);
            }
            context.setVariable("result", result);
            Expression expression = parser.parseExpression(expressionText);
            Object value = expression.getValue(context);
            return value == null ? null : String.valueOf(value);
        } catch (Exception e) {
            return null;
        }
    }
}
