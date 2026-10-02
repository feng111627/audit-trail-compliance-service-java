package com.github.feng111627.audittrailcomplianceservicejava.tests;

import java.io.PrintStream;
import java.util.ArrayDeque;
import java.util.Deque;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

/**
 * 把测试覆盖的业务点（@DisplayName）与每个用例的通过/失败结果打印到控制台，
 * 形如：[业务点] xxx -> 用例名 ✓。
 */
public class AuditTestPrintingListener implements TestExecutionListener {

    private final PrintStream out = System.out;
    private final ThreadLocal<Deque<String>> stack = ThreadLocal.withInitial(ArrayDeque::new);

    @Override
    public void testPlanExecutionStarted(TestPlan testPlan) {
        out.println();
        out.println("================ 审计留痕能力测试覆盖 ================");
    }

    @Override
    public void executionStarted(TestIdentifier identifier) {
        if (identifier.isContainer() && isBusinessPoint(identifier)) {
            stack.get().push(identifier.getDisplayName());
            out.println("【业务点】" + identifier.getDisplayName());
        }
    }

    @Override
    public void executionFinished(TestIdentifier identifier, TestExecutionResult result) {
        if (identifier.isTest()) {
            String mark = switch (result.getStatus()) {
                case SUCCESSFUL -> "✓ 通过";
                case FAILED -> "✗ 失败";
                case ABORTED -> "~ 跳过";
            };
            out.println("    - " + identifier.getDisplayName() + "  [" + mark + "]");
            if (result.getThrowable().isPresent()) {
                out.println("        原因: " + result.getThrowable().get().getMessage());
            }
        }
        if (identifier.isContainer() && isBusinessPoint(identifier) && !stack.get().isEmpty()) {
            stack.get().pop();
        }
    }

    private boolean isBusinessPoint(TestIdentifier identifier) {
        String name = identifier.getDisplayName();
        return name.startsWith("业务点");
    }

    @Override
    public void testPlanExecutionFinished(TestPlan testPlan) {
        out.println("=====================================================");
        out.println();
    }
}
