<?php
/**
 * Malicious Pattern Definitions
 *
 * Comprehensive patterns for detecting malicious content in WordPress databases
 */

namespace WPScanner\Database\Patterns;

class MaliciousPatterns {

    // Pattern cache to avoid recreating arrays
    private static $code_patterns_cache = null;
    private static $spam_patterns_cache = null;
    private static $url_patterns_cache = null;
    private static $agent_patterns_cache = null;
    private static $oauth_patterns_cache = null;
    private static $all_patterns_cache = null;

    /**
     * Get all malicious code patterns (cached)
     */
    public static function getCodePatterns() {
        if (self::$code_patterns_cache !== null) {
            return self::$code_patterns_cache;
        }

        self::$code_patterns_cache = [
            'obfuscation' => [
                'base64' => '/eval\s*\(\s*base64_decode\s*\(/i',
                'gzinflate' => '/gzinflate\s*\(\s*base64_decode/i',
                'str_rot13' => '/str_rot13\s*\(/i',
                'hex_obfuscation' => '/\\\\x[0-9a-f]{2}/i',
                'unicode_obfuscation' => '/\\\\u[0-9a-f]{4}/i'
            ],
            'php_execution' => [
                'eval' => '/eval\s*\(/i',
                'assert' => '/assert\s*\(/i',
                'create_function' => '/create_function\s*\(/i',
                'preg_replace_e' => '/preg_replace\s*\(.*\/e/i',
                'system' => '/system\s*\(/i',
                'exec' => '/exec\s*\(/i',
                'shell_exec' => '/shell_exec\s*\(/i',
                'passthru' => '/passthru\s*\(/i',
                'proc_open' => '/proc_open\s*\(/i'
            ],
            'file_operations' => [
                'file_get_contents' => '/file_get_contents\s*\(/i',
                'file_put_contents' => '/file_put_contents\s*\(/i',
                'fwrite' => '/fwrite\s*\(/i',
                'fputs' => '/fputs\s*\(/i',
                'curl' => '/curl_exec\s*\(/i'
            ],
            'backdoors' => [
                'c99' => '/c99sh|c99shell|r57shell|b374k/i',
                'wso' => '/wso\s*shell|FilesMan|WSO/i',
                'password_backdoor' => '/\$_(GET|POST|REQUEST)\[\'(pass|password|pwd)\'\]/i',
                'command_backdoor' => '/\$_(GET|POST|REQUEST)\[\'(cmd|command|exec)\'\]/i'
            ],
            'sql_injection' => [
                'union_select' => '/UNION.*SELECT/i',
                'sql_comment' => '/\/\*.*\*\/|--|\#/i',
                'concat_sql' => '/CONCAT\s*\(/i'
            ]
        ];

        return self::$code_patterns_cache;
    }

    /**
     * Get spam content patterns (cached)
     */
    public static function getSpamPatterns() {
        if (self::$spam_patterns_cache !== null) {
            return self::$spam_patterns_cache;
        }

        self::$spam_patterns_cache = [
            'pharmaceutical' => [
                '/viagra|cialis|levitra|kamagra/i',
                '/pharmacy|pills|medication/i',
                '/erectile\s+dysfunction/i'
            ],
            'gambling' => [
                '/casino|poker|slots|betting/i',
                '/lottery|jackpot|gambling/i'
            ],
            'adult_content' => [
                '/porn|xxx|adult|sex/i',
                '/escort|dating|hookup/i'
            ],
            'seo_spam' => [
                '/buy\s+(cheap|online|discount)/i',
                '/wholesale|replica|counterfeit/i',
                '/\[url=|\[link=/i'
            ],
            'hidden_content' => [
                '/<div[^>]*display:\s*none[^>]*>.*?<\/div>/is',
                '/<span[^>]*font-size:\s*0/is',
                '/<iframe[^>]*style="display:none/i'
            ]
        ];

        return self::$spam_patterns_cache;
    }

    /**
     * Get suspicious URL patterns (cached)
     */
    public static function getSuspiciousURLPatterns() {
        if (self::$url_patterns_cache !== null) {
            return self::$url_patterns_cache;
        }

        self::$url_patterns_cache = [
            '/bit\.ly|goo\.gl|tinyurl\.com/i',
            '/\.ru\/|\.cn\/|\.tk\//i',
            '/redirect\.php|go\.php|out\.php/i',
            '/\?goto=|r=http|url=http/i'
        ];

        return self::$url_patterns_cache;
    }

    /**
     * Get malicious user agent patterns (cached)
     */
    public static function getMaliciousUserAgents() {
        if (self::$agent_patterns_cache !== null) {
            return self::$agent_patterns_cache;
        }

        self::$agent_patterns_cache = [
            '/sqlmap|havij|acunetix/i',
            '/nikto|nessus|openvas/i',
            '/masscan|nmap/i'
        ];

        return self::$agent_patterns_cache;
    }

    /**
     * OAuth and JSON suspicious patterns (cached)
     */
    public static function getOAuthPatterns() {
        if (self::$oauth_patterns_cache !== null) {
            return self::$oauth_patterns_cache;
        }

        self::$oauth_patterns_cache = [
            'credentials' => [
                '/"client_secret"\s*:\s*"[^"]+"/i',
                '/"access_token"\s*:\s*"[^"]+"/i',
                '/"refresh_token"\s*:\s*"[^"]+"/i',
                '/"private_key"\s*:\s*"[^"]+"/i'
            ],
            'api_keys' => [
                '/api_key|apikey|api-key/i',
                '/secret_key|secretkey|secret-key/i'
            ]
        ];

        return self::$oauth_patterns_cache;
    }

    /**
     * Get all patterns combined (cached)
     * This is the main method for loading all patterns efficiently
     */
    public static function getPatterns() {
        if (self::$all_patterns_cache !== null) {
            return self::$all_patterns_cache;
        }

        self::$all_patterns_cache = [
            'code' => self::getCodePatterns(),
            'spam' => self::getSpamPatterns(),
            'urls' => self::getSuspiciousURLPatterns(),
            'user_agents' => self::getMaliciousUserAgents(),
            'oauth' => self::getOAuthPatterns()
        ];

        return self::$all_patterns_cache;
    }

    /**
     * Clear all pattern caches
     * Call this when patterns are updated externally
     */
    public static function clearCache() {
        self::$code_patterns_cache = null;
        self::$spam_patterns_cache = null;
        self::$url_patterns_cache = null;
        self::$agent_patterns_cache = null;
        self::$oauth_patterns_cache = null;
        self::$all_patterns_cache = null;
    }

    /**
     * Check if content matches any pattern
     */
    public static function matchesPattern($content, $patterns) {
        foreach ($patterns as $category => $pattern_list) {
            if (is_array($pattern_list)) {
                foreach ($pattern_list as $name => $pattern) {
                    if (is_array($pattern)) {
                        foreach ($pattern as $p) {
                            if (preg_match($p, $content)) {
                                return [
                                    'matched' => true,
                                    'category' => $category,
                                    'pattern' => $name,
                                    'type' => 'regex'
                                ];
                            }
                        }
                    } else {
                        if (preg_match($pattern, $content)) {
                            return [
                                'matched' => true,
                                'category' => $category,
                                'pattern' => $name,
                                'type' => 'regex'
                            ];
                        }
                    }
                }
            }
        }

        return ['matched' => false];
    }
}
