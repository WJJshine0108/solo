package com.solo.solo_one.config;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Redis 配置类
 * <p>
 * 配置 RedisTemplate 以支持对象序列化
 *
 * @author solo
 * @version 1.0
 */
@Configuration
public class RedisConfig {

    /**
     * 配置 RedisTemplate
     * <p>
     * 使用 JSON 序列化方式存储对象
     * Key 使用 String 序列化
     * Value 使用 JSON 序列化
     *
     * @param connectionFactory Redis 连接工厂
     * @return 配置好的 RedisTemplate
     */
    @Bean
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // 使用内置的 JSON 序列化器
        template.setKeySerializer(StringRedisSerializer.UTF_8);
        template.setValueSerializer(RedisSerializer.json());
        template.setHashKeySerializer(StringRedisSerializer.UTF_8);
        template.setHashValueSerializer(RedisSerializer.json());

        template.afterPropertiesSet();
        return template;
    }


    /**
     * 配置 ObjectMapper
     * <p>
     * 用于全局 JSON 序列化和反序列化
     */
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);
        mapper.activateDefaultTyping(
                LaissezFaireSubTypeValidator.instance,
                ObjectMapper.DefaultTyping.NON_FINAL
        );
        return mapper;
    }
}
