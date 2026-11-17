<?php

namespace App\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use InvalidArgumentException;

/**
 * A phone number stored in one form only: E.164, e.g. "+79123456789".
 *
 * Whatever is assigned ("8 (912) 345-67-89", "912 345 67 89", "+7 912 345-67-89") is reduced
 * to that form on the way in, so two numbers are the same number exactly when the strings are equal.
 * A number without "+" is taken as a Russian one; a foreign number has to start with "+" and its country code.
 *
 * @implements CastsAttributes<?string, ?string>
 */
class PhoneNumber implements CastsAttributes
{
    private const MIN_FOREIGN_DIGITS = 8;

    private const MAX_DIGITS = 15;

    private const RUSSIAN_DIGITS = 11;

    /**
     * Bring a phone number to the "+79123456789" form, or return null when it is not a valid number.
     */
    public static function normalize(?string $phone): ?string
    {
        $phone = trim((string) $phone);

        if ($phone === '' || preg_match('/^\+?[0-9\s().\-]+$/', $phone) !== 1) {
            return null;
        }

        $digits = (string) preg_replace('/\D+/', '', $phone);

        if (str_starts_with($phone, '+')) {
            return static::isInternational($digits) ? '+'.$digits : null;
        }

        if (strlen($digits) === self::RUSSIAN_DIGITS && in_array($digits[0], ['7', '8'], true)) {
            return '+7'.substr($digits, 1);
        }

        if (strlen($digits) === self::RUSSIAN_DIGITS - 1) {
            return '+7'.$digits;
        }

        return null;
    }

    /**
     * The digits of a number written with "+": a country code that does not start with zero,
     * at most 15 digits in all, and exactly 11 for Russia (+7).
     */
    private static function isInternational(string $digits): bool
    {
        if (str_starts_with($digits, '7')) {
            return strlen($digits) === self::RUSSIAN_DIGITS;
        }

        return ! str_starts_with($digits, '0')
            && strlen($digits) >= self::MIN_FOREIGN_DIGITS
            && strlen($digits) <= self::MAX_DIGITS;
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    public function get(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        return $value;
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        return static::normalize((string) $value)
            ?? throw new InvalidArgumentException("[{$value}] is not a valid phone number.");
    }
}
