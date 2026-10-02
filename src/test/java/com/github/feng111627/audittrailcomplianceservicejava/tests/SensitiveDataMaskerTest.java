package com.github.feng111627.audittrailcomplianceservicejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.feng111627.audittrailcomplianceservicejava.mask.SensitiveDataMasker;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** 敏感数据脱敏规则测试。 */
@DisplayName("脱敏能力：手机号 / 证件号 / 密码")
class SensitiveDataMaskerTest {

    private final SensitiveDataMasker masker = new SensitiveDataMasker();

    @Nested
    @DisplayName("场景：手机号")
    class Phone {

        @Test
        @DisplayName("手机号保留前3后4，中间4位打码")
        void 手机号保留前3后4_中间打码() {
            assertEquals("138****8000", masker.mask("13812348000"));
        }

        @Test
        @DisplayName("手机号混在 JSON/文本中也会被脱敏")
        void 手机号混在文本中也会被脱敏() {
            String text = "联系人手机:13812348000, 备用:15998765432";
            String masked = masker.mask(text);
            assertTrue(masked.contains("138****8000"));
            assertTrue(masked.contains("159****5432"));
            assertFalse(masked.contains("13812348000"));
        }

        @Test
        @DisplayName("长度不等于11位的数字不应被误判为手机号")
        void 非手机号数字不应误伤() {
            assertEquals("订单123456789012号", masker.mask("订单123456789012号"));
        }
    }

    @Nested
    @DisplayName("场景：证件号")
    class IdCard {

        @Test
        @DisplayName("18位身份证保留前6后4，中间8位打码")
        void 身份证保留前6后4() {
            // 110101 19900307 123X
            assertEquals("110101********123X", masker.mask("11010119900307123X"));
        }

        @Test
        @DisplayName("record 的 toString 中身份证同样被脱敏")
        void 文本中的身份证被脱敏() {
            String raw = "PlaceOrderRequest[orderId=O-1, idCard=11010119900307123X]";
            String masked = masker.mask(raw);
            assertTrue(masked.contains("110101********123X"));
            assertFalse(masked.contains("19900307"));
        }
    }

    @Nested
    @DisplayName("场景：密码/密钥")
    class Password {

        @Test
        @DisplayName("password=xxx 形式的值整体打码")
        void 键值对密码整体打码() {
            String masked = masker.mask("login payload password=SuperSecret123 ok");
            assertTrue(masked.contains("password=******"));
            assertFalse(masked.contains("SuperSecret123"));
        }

        @Test
        @DisplayName("JSON 风格 pwd 字段整体打码")
        void json风格密码字段打码() {
            String masked = masker.mask("{\"pwd\":\"abc-42-secret\"}");
            assertTrue(masked.contains("\"pwd\":\"******\""));
            assertFalse(masked.contains("abc-42-secret"));
        }

        @Test
        @DisplayName("按字段名取值时密码字段整体打码，普通字段走内容脱敏")
        void 按字段名脱敏() {
            assertEquals("******", masker.maskValue("password", "whatever"));
            assertEquals("******", masker.maskValue("oldPwd", "whatever"));
            assertEquals("138****8000", masker.maskValue("phone", "13812348000"));
        }
    }
}
