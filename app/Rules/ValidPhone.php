<?php

namespace App\Rules;

use App\Casts\PhoneNumber;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * A phone number that can be stored: a Russian one in any common way of writing it,
 * or a foreign one that starts with "+" and the country code.
 */
class ValidPhone implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value) || PhoneNumber::normalize($value) === null) {
            $fail('Введите телефон, например +7 912 345-67-89. Иностранный номер пишется с «+» и кодом страны.');
        }
    }
}
