<?php

namespace Webkul\Core\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use enshrined\svgSanitize\data\AllowedAttributes;
use enshrined\svgSanitize\data\AllowedTags;
use enshrined\svgSanitize\Sanitizer as MainSanitizer;
use Webkul\Core\Enum\SecurityConfig;

/**
 * Middleware to validate and sanitize file uploads
 */
class SanitizeFileUploads
{
    /**
     * Allowed file extensions for uploads
     *
     * @var array
     */
    protected $allowedExtensions = [];

    /**
     * Dangerous MIME types
     *
     * @var array
     */
    protected $dangerousMimeTypes = [];

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
            $this->allowedExtensions = SecurityConfig::$ALLOWED_EXTENSIONS;

            $this->validateAllFiles($request);
        }

        return $next($request);
    }

    /**
     * Validate all uploaded files in the request
     */
    protected function validateAllFiles(Request $request): void
    {
        $files = $request->allFiles();

        foreach ($files as $key => $file) {
            if (is_array($file)) {
                foreach ($file as $index => $singleFile) {
                    if ($singleFile instanceof UploadedFile) {
                        $this->validateFile($singleFile, "{$key}.{$index}");
                    }
                }
            } elseif ($file instanceof UploadedFile) {
                $this->validateFile($file, $key);
            }
        }
    }

    /**
     * Validate a single uploaded file
     */
    protected function validateFile(UploadedFile $file, string $fieldName): void
    {
        $originalName = $file->getClientOriginalName();
        $extension = strtolower($file->getClientOriginalExtension());

        /**
         * Check for path traversal attempts
         */
        if (preg_match('/\.\.|\/|\\\\/', $originalName)) {
            abort(400, 'File name contains invalid characters.');
        }

        /**
         * Additional validation for image files
         */
        if (! $this->isImageExtension($extension)) {
            abort(400, 'File extension does not match file content.');
        }

        /**
         * Sanitize SVG files after validation
         */
        if ($extension === 'svg') {
            $this->sanitizeSvgFile($file, $fieldName);
        }
    }

    /**
     * Check if extension is an image type
     */
    protected function isImageExtension(string $extension): bool
    {
        return in_array($extension, SecurityConfig::$ALLOWED_EXTENSIONS);
    }

    /**
     * Sanitize SVG file to remove potentially malicious content.
     * Integrated from Sanitizer trait for unified file handling.
     */
    protected function sanitizeSvgFile(UploadedFile $file, string $fieldName): void
    {
        try {
            $svgContent = file_get_contents($file->getRealPath());

            if (! $svgContent) {
                return;
            }

            $sanitizer = new MainSanitizer;
            $sanitizer->setAllowedAttrs(new AllowedAttributes);
            $sanitizer->setAllowedTags(new AllowedTags);
            $sanitizer->minify(true);
            $sanitizer->removeRemoteReferences(true);
            $sanitizer->removeXMLTag(true);
            $sanitizer->setXMLOptions(LIBXML_NONET | LIBXML_NOBLANKS);

            $sanitizedContent = $sanitizer->sanitize($svgContent);

            if ($sanitizedContent === false) {
                // Fallback pattern-based sanitization
                $patterns = [
                    '/<script\b[^>]*>(.*?)<\/script>/is',
                    '/\bon\w+\s*=\s*["\'][^"\']*["\']/i',
                    '/javascript\s*:/i',
                    '/data\s*:[^,]*base64/i',
                ];

                $sanitizedContent = $svgContent;

                foreach ($patterns as $pattern) {
                    $sanitizedContent = preg_replace($pattern, '', $sanitizedContent);
                }

                file_put_contents($file->getRealPath(), $sanitizedContent);

                return;
            }

            // Remove any remaining scripts and event handlers
            $sanitizedContent = preg_replace('/(^<script.*?>.*?<\/script>)|(\son\w+\s*=\s*["\'][^"\']*["\']/is', '', $sanitizedContent);

            file_put_contents($file->getRealPath(), $sanitizedContent);
        } catch (Exception $e) {
            report($e->getMessage());

            abort(400, 'Unable to sanitize SVG file.');
        }
    }
}
