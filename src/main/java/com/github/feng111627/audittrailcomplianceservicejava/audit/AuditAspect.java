package com.github.feng111627.audittrailcomplianceservicejava.audit;

import com.github.feng111627.audittrailcomplianceservicejava.mask.SensitiveDataMasker;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.List;
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

/**
 * 自动留痕切面：拦截所有标注 {@link Audited} 的方法。
 *
 * <p>无论方法正常返回还是抛出异常都会写一条审计记录，并按结果明确分类：
 * <ul>
 *   <li>{@link AuditOutcome#SUCCESS}：正常返回；</li>
 *   <li>{@link AuditOutcome#VALIDATION_REJECTED}：参数校验未通过（IllegalArgumentException 等）——
 *       操作被<b>拒绝</b>；</li>
 *   <li>{@link AuditOutcome#ACCESS_DENIED}：权限不足——操作被<b>拒绝</b>；</li>
 *   <li>{@link AuditOutcome#FAILURE}：业务失败（{@link BusinessFailureException}）——
 *       操作被业务规则拒绝；</li>
 *   <li>{@link AuditOutcome#ERROR}：其他异常——操作被<b>中断</b>，记录异常类型与脱敏后的消息。</li>
 * </ul>
 *
 * <p>进入方法时压入新 span 并记录开始时间，退出时弹栈，保证嵌套调用的归属与先后正确。
 * 异常一定会原样向上抛出，审计只是旁路记录，不改变业务语义。
 */
@Aspect
@Component
public class AuditAspect {

    private final AuditService auditService;
    private final SensitiveDataMasker masker;
    private final ExpressionParser parser = new SpelExpressionParser();
    private final ParameterNameDiscoverer paramNames = new DefaultParameterNameDiscoverer();

    public AuditAspect(AuditService auditService, SensitiveDataMasker masker) {
        this.auditService = auditService;
        this.masker = masker;
    }

    @Around("@annotation(audited)")
    public Object around(ProceedingJoinPoint pjp, Audited audited) throws Throwable {
        AuditContext context = AuditContextHolder.get();
        // 脱离过滤器/未经过 Web 的直接调用也不能漏记：建立临时上下文。
        if (context == null) {
            context = AuditContext.startNew(null, null);
            AuditContextHolder.set(context);
        }
        context.pushSpan();
        long start = System.nanoTime();
        Object result;
        try {
            result = pjp.proceed();
        } catch (Throwable ex) {
            long durationMs = (System.nanoTime() - start) / 1_000_000;
            recordFailure(pjp, audited, context, ex, durationMs);
            throw ex;
        }
        long durationMs = (System.nanoTime() - start) / 1_000_000;
        AuditRecordCommand command = new AuditRecordCommand(
                audited.action(),
                audited.resourceType(),
                resolveResourceId(pjp, audited),
                audited.recordParams() ? buildParams(pjp) : null,
                AuditOutcome.SUCCESS,
                "OK",
                null,
                durationMs
        );
        auditService.record(command);
        context.popSpan();
        return result;
    }

    private void recordFailure(ProceedingJoinPoint pjp, Audited audited, AuditContext context,
                               Throwable ex, long durationMs) {
        AuditOutcome outcome;
        String reasonCode;
        if (ex instanceof AccessDeniedException ade) {
            outcome = AuditOutcome.ACCESS_DENIED;
            reasonCode = "ACCESS_DENIED_" + ade.reason().name();
        } else if (ex instanceof BusinessFailureException) {
            outcome = AuditOutcome.FAILURE;
            reasonCode = "BUSINESS_FAILURE";
        } else if (ex instanceof IllegalArgumentException) {
            outcome = AuditOutcome.VALIDATION_REJECTED;
            reasonCode = "VALIDATION_REJECTED";
        } else {
            outcome = AuditOutcome.ERROR;
            reasonCode = "ERROR:" + ex.getClass().getSimpleName();
        }
        try {
            AuditRecordCommand command = new AuditRecordCommand(
                    audited.action(),
                    audited.resourceType(),
                    resolveResourceId(pjp, audited),
                    audited.recordParams() ? buildParams(pjp) : null,
                    outcome,
                    reasonCode,
                    // 异常消息里也可能带手机号/密码，落库前脱敏。
                    masker.mask(ex.getMessage()),
                    durationMs
            );
            auditService.record(command);
        } finally {
            // 记录本身出问题也不能影响异常的原始传播；span 必须弹掉。
            context.popSpan();
        }
    }

    /** 用 SpEL 解析资源标识表达式，变量名为方法参数名（如 {@code #request.orderId()}）。 */
    private String resolveResourceId(ProceedingJoinPoint pjp, Audited audited) {
        String expr = audited.resourceIdExpr();
        if (expr == null || expr.isBlank()) {
            return null;
        }
        try {
            MethodSignature signature = (MethodSignature) pjp.getSignature();
            Method method = signature.getMethod();
            EvaluationContext ctx = new StandardEvaluationContext();
            String[] names = paramNames.getParameterNames(method);
            Object[] args = pjp.getArgs();
            if (names != null) {
                for (int i = 0; i < names.length && i < args.length; i++) {
                    ctx.setVariable(names[i], args[i]);
                }
            }
            Expression expression = parser.parseExpression(expr);
            Object value = expression.getValue(ctx);
            return value == null ? null : value.toString();
        } catch (RuntimeException e) {
            // 表达式解析失败不应阻断业务与留痕本身。
            return "<unresolvable:" + expr + ">";
        }
    }

    /** 拼装入参文本：参数名=值，逐值脱敏。 */
    private String buildParams(ProceedingJoinPoint pjp) {
        MethodSignature signature = (MethodSignature) pjp.getSignature();
        String[] names = paramNames.getParameterNames(signature.getMethod());
        Object[] args = pjp.getArgs();
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            String name = (names != null && i < names.length) ? names[i] : "arg" + i;
            String value;
            if (args[i] == null) {
                value = "null";
            } else {
                value = masker.maskValue(name, String.valueOf(args[i]));
            }
            parts.add(name + "=" + value);
        }
        return String.join(", ", parts);
    }
}
