<?php
/**
 * Malicious Pattern Definitions
 *
 * Comprehensive patterns for detecting malicious content in WordPress databases
 */

namespace WPScanner\Database\Patterns;

class MaliciousPatterns {

    /**
     * Get all malicious code patterns
     */
    public static function getCodePatterns() {
        return [
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
    }

    /**
     * Get spam content patterns
     */
    public static function getSpamPatterns() {
        return [
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
    }

    /**
     * Get suspicious URL patterns
     */
    public static function getSuspiciousURLPatterns() {
        return [
            '/bit\.ly|goo\.gl|tinyurl\.com/i',
            '/\.ru\/|\.cn\/|\.tk\//i',
            '/redirect\.php|go\.php|out\.php/i',
            '/\?goto=|r=http|url=http/i'
        ];
    }

    /**
     * Get malicious user agent patterns
     */
    public static function getMaliciousUserAgents() {
        return [
            '/sqlmap|havij|acunetix/i',
            '/nikto|nessus|openvas/i',
            '/masscan|nmap/i'
        ];
    }

    /**
     * OAuth and JSON suspicious patterns
     */
    public static function getOAuthPatterns() {
        return [
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
    }

    /**
     * Get all patterns combined
     */
    public static function getPatterns() {
        return [
            'code' => self::getCodePatterns(),
            'spam' => self::getSpamPatterns(),
            'urls' => self::getSuspiciousURLPatterns(),
            'user_agents' => self::getMaliciousUserAgents(),
            'oauth' => self::getOAuthPatterns()
        ];
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
