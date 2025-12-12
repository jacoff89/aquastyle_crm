<?php

namespace Webkul\Core\Enum;

final class SecurityConfig
{
    /**
     * Regex patterns considered dangerous in user-provided strings
     *
     * @var array<int, string>
     */
    public static array $DANGEROUS_PATTERNS = [
        '/<script\b[^>]*>.*?<\/script>/is',
        '/<iframe\b[^>]*>.*?<\/iframe>/is',
        '/<object\b[^>]*>.*?<\/object>/is',
        '/<embed\b[^>]*>.*?<\/embed>/is',
        '/<applet\b[^>]*>.*?<\/applet>/is',
        '/javascript:/i',
        '/on\w+\s*=\s*/i',
        '/<link\b[^>]*>/is',
        '/<style\b[^>]*>.*?<\/style>/is',
        '/<meta\b[^>]*>/is',
        '/document\.cookie/i',
        '/document\.write/i',
        '/window\.location/i',
        '/eval\s*\(/i',
        '/expression\s*\(/i',
        '/<form\b[^>]*>/is',
        '/<\/form>/i',
        '/<input\b[^>]*>/is',
        '/<textarea\b[^>]*>/is',
        '/<select\b[^>]*>/is',
        '/<button\b[^>]*>/is',
        '/vbscript:/i',
        '/data:text\/html/i',
    ];

    /**
     * Fields that may legitimately contain HTML content
     *
     * @var array<int, string>
     */
    public static array $HTML_FIELDS = [
        'description',
        'content',
        'body',
        'message',
        'notes',
        'reply',
    ];

    /**
     * Allowed file extensions for uploads
     *
     * @var array<int, string>
     */
    public static array $ALLOWED_EXTENSIONS = [
        'jpg',
        'jpeg',
        'png',
        'gif',
        'webp',
        'svg',
        'pdf',
        'doc',
        'docx',
        'xls',
        'xlsx',
        'ppt',
        'csv',
        'odt',
        'ods',
        'odp',
        'zip',
        'rar',
        'tar',
        'json',
        'mp4',
        'mp3',
    ];

    /**
     * Valid image mime types mapped by extension
     *
     * @var array<string, array<int, string>>
     */
    public static array $VALID_IMAGE_MIME_TYPES = [
        'jpg'  => ['image/jpeg', 'image/pjpeg'],
        'jpeg' => ['image/jpeg', 'image/pjpeg'],
        'png'  => ['image/png'],
        'gif'  => ['image/gif'],
        'bmp'  => ['image/bmp', 'image/x-windows-bmp'],
        'webp' => ['image/webp'],
        'ico'  => ['image/x-icon', 'image/vnd.microsoft.icon'],
    ];
}
