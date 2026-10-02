package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.assertj.core.api.Assertions.assertThat;

import com.github.feng111627.audittrailcomplianceservicejava.audit.annotation.Sensitive.SensitiveType;
import com.github.feng111627.audittrailcomplianceservicejava.audit.masking.DefaultMaskingService;
import com.github.feng111627.audittrailcomplianceservicejava.demo.CreateOrderRequest;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * 业务点：脱敏规则（手机号/证件号/密码）、记录递归脱敏、参数名兜底识别。
 */
@DisplayName("业务点-敏感数据脱敏")
class SensitiveMaskingTest {

    private DefaultMaskingService masking;

    @BeforeEach
    void setUp() {
        masking = new DefaultMaskingService();
    }

    @Nested
    @DisplayName("字符串规则")
    class StringRules {

        @Test
        @DisplayName("手机号保留前3后4，中间星号")
        void phoneMasked() {
            assertThat(masking.mask("13812341234", SensitiveType.PHONE))
                    .isEqualTo("138****1234");
        }

        @Test
        @DisplayName("证件号保留前6后4")
        void idCardMasked() {
            assertThat(masking.mask("110101199003078888", SensitiveType.ID_CARD))
                    .isEqualTo("110101********8888");
        }

        @Test
        @DisplayName("密码一律星号，不泄露长度")
        void passwordMasked() {
            assertThat(masking.mask("supersecret", SensitiveType.PASSWORD))
                    .isEqualTo("******");
        }
    }

    @Test
    @DisplayName("含 @Sensitive 的记录对象递归脱敏，手机号与密码均不出现原值")
    void recordObjectMasked() {
        CreateOrderRequest request = new CreateOrderRequest(
                "alice", "book", "13812341234", "paypass");
        Object masked = masking.maskObject(request);

        String text = masked.toString();
        assertThat(text).contains("138****1234").contains("******");
        assertThat(text).doesNotContain("13812341234").doesNotContain("paypass");
    }

    @Test
    @DisplayName("参数名兜底：password/phone/idCard 自动脱敏，支持集合嵌套")
    void parameterNameHeuristic() {
        Map<String, Object> raw = Map.of(
                "loginPassword", "abc12345",
                "mobile", "13999998888",
                "users", List.of(Map.of("idCardNo", "110101199003071234")));

        Map<String, Object> masked = masking.maskParameters(raw);
        String text = masked.toString();

        assertThat(text).contains("******").contains("139****8888")
                .contains("110101********1234");
        assertThat(text).doesNotContain("abc12345").doesNotContain("13999998888");
    }
}
