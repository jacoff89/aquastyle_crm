<?php

namespace Webkul\Core\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Webkul\Core\Enum\SecurityConfig;

class SanitizeInput
{
    /**
     * Dangerous patterns that should be completely removed
     *
     * @var array
     */
    protected $dangerousPatterns = [];

    /**
     * Fields that should be excluded from sanitization
     * (e.g., rich text fields that need HTML)
     *
     * @var array
     */
    protected $excludedFields = [
        '_token',
        '_method',
        'password',
        'password_confirmation',
    ];

    /**
     * Fields that may contain legitimate HTML (like WYSIWYG editors)
     * These will receive special sanitization
     *
     * @var array
     */
    protected $htmlFields = [];

    /**
     * Handle an incoming request.
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        if ($request->isMethod('post')
            || $request->isMethod('put')
            || $request->isMethod('patch')) {
            $this->htmlFields = SecurityConfig::$HTML_FIELDS;

            $input = $request->except($this->excludedFields);

            $sanitized = $this->sanitizeArray($input);

            $request->merge($sanitized);
        }

        return $next($request);
    }

    /**
     * Recursively sanitize an array of data
     */
    protected function sanitizeArray(array $data, string $parentKey = ''): array
    {
        $sanitized = [];

        foreach ($data as $key => $value) {
            $fullKey = $parentKey ? "{$parentKey}.{$key}" : $key;

            if (is_array($value)) {
                $sanitized[$key] = $this->sanitizeArray($value, $fullKey);
            } elseif (is_string($value)) {
                $sanitized[$key] = $this->sanitizeString($value, $key);
            } else {
                $sanitized[$key] = $value;
            }
        }

        return $sanitized;
    }

    /**
     * Sanitize a string value
     */
    protected function sanitizeString(string $value, string $key): string
    {
        /**
         * If the field is in the HTML fields list, use HTML purifier
         */
        if (in_array($key, $this->htmlFields)) {
            return $this->sanitizeHtml($value);
        }

        return $this->removeDangerousContent($value);
    }

    /**
     * Remove dangerous content from string
     */
    protected function removeDangerousContent(string $value): string
    {
        /**
         * Remove dangerous patterns (from centralized config)
         */
        foreach (SecurityConfig::$DANGEROUS_PATTERNS as $pattern) {
            $value = preg_replace($pattern, '', $value);
        }

        $decoded = html_entity_decode($value, ENT_QUOTES, 'UTF-8');

        foreach (SecurityConfig::$DANGEROUS_PATTERNS as $pattern) {
            if (preg_match($pattern, $decoded)) {
                $value = strip_tags($value);

                break;
            }
        }

        $value = str_replace(chr(0), '', $value);

        $value = trim($value);

        return $value;
    }

    /**
     * Sanitize HTML content (for rich text fields)
     */
    protected function sanitizeHtml(string $value): string
    {
        if (class_exists('\HTMLPurifier')) {
            $config = \HTMLPurifier_Config::createDefault();
            $config->set('HTML.Allowed', 'p,b,strong,i,em,u,a[href|title],ul,ol,li,br,span[style],div[style],h1,h2,h3,h4,h5,h6,table,tr,td,th,thead,tbody,blockquote,code,pre');
            $config->set('CSS.AllowedProperties', 'color,background-color,font-size,font-weight,text-align,margin,padding,border');
            $config->set('AutoFormat.RemoveEmpty', true);
            $config->set('AutoFormat.AutoParagraph', false);

            $purifier = new \HTMLPurifier($config);

            return $purifier->purify($value);
        }

        $value = preg_replace('/<([a-z]+)([^>]*?)on\w+\s*=\s*["\'].*?["\']/i', '<$1$2', $value);
        $value = preg_replace('/<([a-z]+)([^>]*?)javascript:/i', '<$1$2', $value);

        return $this->removeDangerousContent($value);
    }
}
