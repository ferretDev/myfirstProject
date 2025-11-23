<?php
/**
 * Logging Utility
 */

namespace WPScanner\Utils;

class Logger {

    private $log_file;
    private $level;

    const DEBUG = 1;
    const INFO = 2;
    const WARNING = 3;
    const ERROR = 4;
    const CRITICAL = 5;

    public function __construct($log_file = null, $level = self::INFO) {
        $this->log_file = $log_file ?: WP_SCANNER_DIR . '/logs/scanner.log';
        $this->level = $level;

        // Ensure log directory exists
        $log_dir = dirname($this->log_file);
        if (!is_dir($log_dir)) {
            mkdir($log_dir, 0755, true);
        }
    }

    public function debug($message, $context = []) {
        $this->log(self::DEBUG, $message, $context);
    }

    public function info($message, $context = []) {
        $this->log(self::INFO, $message, $context);
    }

    public function warning($message, $context = []) {
        $this->log(self::WARNING, $message, $context);
    }

    public function error($message, $context = []) {
        $this->log(self::ERROR, $message, $context);
    }

    public function critical($message, $context = []) {
        $this->log(self::CRITICAL, $message, $context);
    }

    private function log($level, $message, $context = []) {
        if ($level < $this->level) {
            return;
        }

        $level_name = $this->getLevelName($level);
        $timestamp = date('Y-m-d H:i:s');

        $log_entry = sprintf(
            "[%s] [%s] %s %s\n",
            $timestamp,
            $level_name,
            $message,
            !empty($context) ? json_encode($context) : ''
        );

        file_put_contents($this->log_file, $log_entry, FILE_APPEND);
    }

    private function getLevelName($level) {
        $levels = [
            self::DEBUG => 'DEBUG',
            self::INFO => 'INFO',
            self::WARNING => 'WARNING',
            self::ERROR => 'ERROR',
            self::CRITICAL => 'CRITICAL',
        ];

        return $levels[$level] ?? 'UNKNOWN';
    }
}
