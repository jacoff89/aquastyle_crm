<?php

namespace Webkul\Core\Enum;

final class SecurityConfig
{
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
