package com.github.feng111627.audittrailcomplianceservicejava.tests;

import java.util.ArrayDeque;
import java.util.Deque;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

/**
 * 测试执行监听器：在控制台以缩进树形式打印
 * “测试类/业务分组（@DisplayName）→ 用例（中文业务点名）→ 通过/失败/跳过”，
 * 让 {@code mvn test} 的输出能直接看出覆盖了哪些业务点及各自的通过情况。
 */
public class BusinessPointTestListener implements TestExecutionListener {

    private static final String GREEN = "\u001B[32m";
    private static final String RED = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";
    private static final String RESET = "\u001B[0m";

    private final Deque<String> stack = new ArrayDeque<>();

    @Override
    public void testPlanExecutionStarted(TestPlan testPlan) {
        System.out.println();
        System.out.println("========== 审计能力测试：业务点覆盖与用例通过情况 ==========");
    }

    @Override
    public void executionStarted(TestIdentifier identifier) {
        String display = identifier.getDisplayName();
        if (identifier.isContainer() && isBusinessContainer(display)) {
            System.out.println("  ".repeat(stack.size()) + "● " + display);
            stack.push(display);
        } else if (identifier.isTest()) {
            System.out.print("  ".repeat(stack.size() + 1) + "• " + display + " ... ");
        }
    }

    @Override
    public void executionFinished(TestIdentifier identifier, TestExecutionResult result) {
        if (identifier.isTest()) {
            switch (result.getStatus()) {
                case SUCCESSFUL -> System.out.println(GREEN + "通过 ✓" + RESET);
                case FAILED -> System.out.println(RED + "失败 ✗ "
                        + result.getThrowable().map(Throwable::getMessage).orElse("") + RESET);
                case ABORTED -> System.out.println(YELLOW + "中止" + RESET);
            }
        } else if (identifier.isContainer() && isBusinessContainer(identifier.getDisplayName())) {
            if (!stack.isEmpty()) {
                stack.pop();
            }
        }
    }

    @Override
    public void executionSkipped(TestIdentifier identifier, String reason) {
        if (identifier.isTest()) {
            System.out.println("  ".repeat(stack.size() + 1) + "• "
                    + identifier.getDisplayName() + " ... " + YELLOW + "跳过 (" + reason + ")" + RESET);
        }
    }

    /** 只展示带中文业务语义的容器（类与 @Nested 组），过滤 JUnit 内部容器。 */
    private boolean isBusinessContainer(String display) {
        return display != null && display.chars().anyMatch(c -> c >= 0x4E00 && c <= 0x9FFF);
    }
}
